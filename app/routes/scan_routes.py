from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
import os
import re

import base_datos
import motor_escaneo
from app.extensions import limiter
from app.services.email_service import EmailDeliveryError, enviar_correo_con_adjunto
from app.services.pdf_service import PdfGenerationError, html_a_pdf_bytes
from app.utils.urls import construir_y_validar_url, obtener_protocolo_desde_url

scan_bp = Blueprint('scan', __name__)

SCAN_LIMIT_INTERVAL = os.getenv('SCAN_LIMIT_INTERVAL', '1 per 20 seconds')
SCAN_LIMIT_HOURLY = os.getenv('SCAN_LIMIT_HOURLY', '15 per hour')
REPORT_SEND_LIMIT_INTERVAL = os.getenv(
    'REPORT_SEND_LIMIT_INTERVAL', '1 per 60 seconds')
REPORT_SEND_LIMIT_HOURLY = os.getenv('REPORT_SEND_LIMIT_HOURLY', '5 per hour')


def _hallazgos_para_bd(resultados):
    hallazgos = []
    for res in resultados:
        tipo = str(res.get('tipo', '')).strip()
        if not tipo or tipo == 'Ninguna detectada':
            continue
        hallazgos.append({
            'tipo': tipo,
            'severidad': str(res.get('severidad', '') or '').strip(),
            'parametro': str(res.get('parametro', '') or ''),
            'payload': str(res.get('payload', '') or ''),
        })
    return hallazgos


def _formatear_resultado_para_usuario(resultado):
    item = dict(resultado)
    tipo = str(item.get('tipo', ''))
    descripcion = str(item.get('descripcion', ''))

    if tipo == 'VirusTotal URL Reputation':
        item['tipo'] = 'Reputacion de URL (VirusTotal)'

        patron = (
            r'malicious:\s*(\d+),\s*suspicious:\s*(\d+),\s*'
            r'harmless:\s*(\d+),\s*undetected:\s*(\d+)'
        )
        match = re.search(patron, descripcion, flags=re.IGNORECASE)
        if match:
            maliciosos, sospechosos, seguros, sin_detectar = match.groups()
            item['severidad'] = motor_escaneo.calcular_severidad_virustotal(
                maliciosos,
                sospechosos,
                seguros,
                sin_detectar,
            )
            item['descripcion'] = (
                'Motores de seguridad: '
                f'maliciosos {maliciosos}, sospechosos {sospechosos}, '
                f'seguros {seguros}, sin deteccion {sin_detectar}.'
            )
        elif descripcion:
            item['descripcion'] = 'Analisis de reputacion completado en VirusTotal.'

    elif tipo == 'VirusTotal':
        item['tipo'] = 'Estado de VirusTotal'
        if descripcion:
            item['descripcion'] = 'No fue posible completar la consulta de VirusTotal en este intento.'

    return item


def _formatear_resultados_para_usuario(resultados):
    return [_formatear_resultado_para_usuario(r) for r in resultados]


def _normalizar_severidad_pdf(severidad):
    valor = str(severidad or '').strip().lower()
    if valor in ('critico', 'crítico'):
        return 'Critico'
    if valor in ('alto', 'alta'):
        return 'Alto'
    if valor == 'medio':
        return 'Medio'
    if valor == 'bajo':
        return 'Bajo'
    return 'Otro'


def _recomendaciones_especificas_por_hallazgo(hallazgos):
    recomendaciones = []
    vistas = set()

    def add(texto):
        if texto and texto not in vistas:
            recomendaciones.append(texto)
            vistas.add(texto)

    for hallazgo in hallazgos:
        tipo_raw = str(hallazgo.get('tipo', '')).strip().lower()
        descripcion_raw = str(hallazgo.get('descripcion', '')).strip().lower()
        sev = _normalizar_severidad_pdf(hallazgo.get('severidad'))

        if 'sql' in tipo_raw or 'inyeccion sql' in tipo_raw:
            add('SQLi: Migrar todas las consultas a sentencias preparadas/parametrizadas y prohibir concatenacion directa de entrada de usuario en SQL.')
            add('SQLi: Aplicar validacion de entrada por lista blanca (allowlist) para parametros criticos y normalizar tipos antes de llegar a la capa de datos.')
            add('SQLi: Restringir privilegios del usuario de base de datos (principio de minimo privilegio) para limitar impacto en caso de explotacion.')

        if 'xss' in tipo_raw:
            add('XSS: Escapar contexto de salida (HTML, atributos, JS y URL) con librerias de plantillas seguras antes de renderizar datos controlados por usuario.')
            add('XSS: Implementar Content-Security-Policy estricta (sin inline scripts) y activar protecciones complementarias como X-Content-Type-Options.')
            add('XSS: Sanitizar entrada rica en HTML con una lista blanca de etiquetas/atributos permitidos (ej. Bleach) antes de persistir.')

        if 'virustotal' in tipo_raw or 'reputacion' in tipo_raw or 'reputation' in tipo_raw:
            add('Reputacion de URL: Verificar blacklist/feeds adicionales (Google Safe Browsing, URLHaus, PhishTank) para confirmar si el hallazgo es falso positivo o riesgo real.')
            add('Reputacion de URL: Revisar DNS, WHOIS y certificados TLS del dominio para detectar indicadores de compromiso o infraestructura sospechosa.')
            add('Reputacion de URL: Si el sitio es legitimo, solicitar reclasificacion en motores que reportan falso positivo y documentar evidencias.')

        if 'header' in tipo_raw or 'cabecera' in tipo_raw:
            add('Cabeceras de seguridad: Configurar HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy y Permissions-Policy en el servidor web/proxy.')

        if 'csrf' in tipo_raw:
            add('CSRF: Exigir token anti-CSRF por formulario/sesion y validar origen/referer en operaciones de cambio de estado.')

        if 'ssl' in tipo_raw or 'tls' in tipo_raw or 'certificado' in descripcion_raw:
            add('TLS: Forzar TLS 1.2+ con suites robustas, renovar certificados antes de expiracion y deshabilitar protocolos/cifrados obsoletos.')

        if sev in ('Critico', 'Alto'):
            add('Prioridad alta: Definir ventana de remediacion inmediata (24-72h), agregar pruebas de regresion y verificar correccion con reescaneo posterior.')

    # Recomendaciones transversales para elevar madurez de seguridad.
    add('Monitoreo: Centralizar logs de aplicacion y seguridad con alertas (SIEM) para detectar intentos repetidos de explotacion.')
    add('SDLC seguro: Integrar SAST/DAST en CI/CD y bloquear despliegues con vulnerabilidades criticas sin excepcion aprobada.')
    add('Hardening: Mantener dependencias actualizadas y ejecutar escaneo de vulnerabilidades de librerias de forma periodica.')

    return recomendaciones


def _construir_resumen_pdf(reporte):
    hallazgos = reporte.get('hallazgos', []) or []
    total = len(hallazgos)

    severidades = {
        'Critico': 0,
        'Alto': 0,
        'Medio': 0,
        'Bajo': 0,
        'Otro': 0,
    }

    tipos = {}
    recomendaciones = []
    recomendaciones_vistas = set()

    for hallazgo in hallazgos:
        sev = _normalizar_severidad_pdf(hallazgo.get('severidad'))
        severidades[sev] += 1

        tipo = str(hallazgo.get('tipo', 'Hallazgo')).strip() or 'Hallazgo'
        tipos[tipo] = tipos.get(tipo, 0) + 1

        recomendacion = str(hallazgo.get('recomendacion', '')).strip()
        if recomendacion and recomendacion not in recomendaciones_vistas:
            recomendaciones.append(recomendacion)
            recomendaciones_vistas.add(recomendacion)

    if not recomendaciones:
        recomendaciones = [
            'Mantener framework, librerías y dependencias en su versión más reciente.',
            'Validar y sanear entradas en backend para reducir exposición a inyección.',
            'Implementar encabezados de seguridad HTTP y política CSP estricta.',
        ]

    recomendaciones_especificas = _recomendaciones_especificas_por_hallazgo(
        hallazgos)
    for item in recomendaciones_especificas:
        if item not in recomendaciones_vistas:
            recomendaciones.append(item)
            recomendaciones_vistas.add(item)

    puntaje_raw = 100 - (total * 20)
    puntaje = max(0, min(100, puntaje_raw))

    if total == 0:
        riesgo = 'Bajo'
    elif total <= 2:
        riesgo = 'Medio'
    else:
        riesgo = 'Elevado'

    total_conteo = max(1, total)
    grafica = [
        {
            'nombre': 'Critico',
            'valor': severidades['Critico'],
            'porcentaje': round((severidades['Critico'] / total_conteo) * 100, 1),
            'color': '#ef4444',
        },
        {
            'nombre': 'Alto',
            'valor': severidades['Alto'],
            'porcentaje': round((severidades['Alto'] / total_conteo) * 100, 1),
            'color': '#f97316',
        },
        {
            'nombre': 'Medio',
            'valor': severidades['Medio'],
            'porcentaje': round((severidades['Medio'] / total_conteo) * 100, 1),
            'color': '#eab308',
        },
        {
            'nombre': 'Bajo',
            'valor': severidades['Bajo'],
            'porcentaje': round((severidades['Bajo'] / total_conteo) * 100, 1),
            'color': '#38bdf8',
        },
    ]

    for item in grafica:
        bloques_totales = 24
        bloques_llenos = int(
            round((item['porcentaje'] / 100) * bloques_totales))
        bloques_llenos = max(0, min(bloques_totales, bloques_llenos))

        item['bloques_llenos'] = bloques_llenos
        item['bloques_vacios'] = bloques_totales - bloques_llenos

        if item['nombre'] == 'Critico':
            item['clase_barra'] = 'bar-critico'
        elif item['nombre'] == 'Alto':
            item['clase_barra'] = 'bar-alto'
        elif item['nombre'] == 'Medio':
            item['clase_barra'] = 'bar-medio'
        else:
            item['clase_barra'] = 'bar-bajo'

    top_tipos = sorted(
        tipos.items(), key=lambda item: item[1], reverse=True)[:5]

    return {
        'puntaje': puntaje,
        'riesgo': riesgo,
        'total_hallazgos': total,
        'severidades': severidades,
        'grafica': grafica,
        'top_tipos': top_tipos,
        'recomendaciones': recomendaciones[:12],
    }


@scan_bp.route('/api/escanear', methods=['POST'])
@limiter.limit(SCAN_LIMIT_HOURLY)
@limiter.limit(SCAN_LIMIT_INTERVAL)
def api_escanear():
    try:
        admin_id = session.get('admin_id')
        if not admin_id:
            return jsonify({'error': 'No autorizado'}), 401

        datos = request.get_json()

        if not datos:
            return jsonify({'error': 'No se recibieron datos'}), 400

        protocolo = datos.get('protocolo', 'https://')
        url_ingresada = datos.get('url', '')

        url_completa, error_validacion = construir_y_validar_url(
            protocolo, url_ingresada)
        if error_validacion:
            return jsonify({'error': error_validacion}), 400

        protocolo_usado = obtener_protocolo_desde_url(url_completa)

        print(f"API - Escaneando: {url_completa}")

        resultados = motor_escaneo.iniciar_escaneo_completo(url_completa)
        resultados_mostrables = _formatear_resultados_para_usuario(resultados)
        total_vulnerabilidades_link = len(
            [r for r in resultados if str(
                r.get('tipo', '')) != 'Ninguna detectada']
        )
        total_criticas_link = len(
            [
                r for r in resultados
                if str(r.get('tipo', '')) != 'Ninguna detectada'
                and str(r.get('severidad', '')).strip().lower() in ('critico', 'crítico', 'alta', 'alto')
            ]
        )

        hallazgos_bd = _hallazgos_para_bd(resultados)
        escaneo_id = base_datos.guardar_analisis_completo(
            url=url_completa,
            protocolo=protocolo_usado,
            administrador_id=admin_id,
            hallazgos_list=hallazgos_bd,
            tiempo_ejecucion=0,
        )

        metricas_usuario = base_datos.obtener_metricas_resumen_usuario(
            admin_id)

        return jsonify({
            'url': url_completa,
            'protocolo': protocolo_usado,
            'resultados': resultados_mostrables,
            'total_vulnerabilidades': total_vulnerabilidades_link,
            'escaneo_id': escaneo_id,
            # Mantiene nombres existentes para no romper frontend, pero con semantica corregida.
            'total_hallazgos_bd': total_vulnerabilidades_link,
            'total_criticas_bd': total_criticas_link,
            'total_escaneos_bd': metricas_usuario['total_escaneos'],
            'escaneos_hoy_bd': metricas_usuario['escaneos_hoy'],
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@scan_bp.route('/api/historial-escaneos', methods=['GET'])
def api_historial_escaneos():
    """Devuelve el historial de escaneos del usuario actual"""
    print("\n" + "="*60)
    print("🚀 API /api/historial-escaneos llamado")
    print("="*60)

    admin_id = session.get('admin_id')
    admin_usuario = session.get('admin_usuario', 'desconocido')

    print(f"👤 Usuario en sesión: ID={admin_id}, Usuario={admin_usuario}")

    if not admin_id:
        print("❌ No autorizado - sesión no encontrada")
        return jsonify({'error': 'No autorizado', 'historial': []}), 401

    try:
        historial = base_datos.obtener_historial_escaneos(admin_id)
        print(f"✅ API - Historial obtenido: {len(historial)} registros")

        return jsonify({'ok': True, 'historial': historial})

    except Exception as e:
        print(f"❌ Error en API historial: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'historial': []}), 500


@scan_bp.route('/api/verificar-url', methods=['POST'])
def verificar_url():
    try:
        datos = request.get_json() or {}
        protocolo = datos.get('protocolo', 'https://')
        url_ingresada = datos.get('url', '')

        url_completa, error_validacion = construir_y_validar_url(
            protocolo, url_ingresada)
        if error_validacion:
            return jsonify({'error': error_validacion}), 400

        try:
            import requests
            response = requests.get(url_completa, timeout=5, verify=True)
            accesible = response.status_code == 200
            return jsonify({
                'url': url_completa,
                'accesible': accesible,
                'status_code': response.status_code
            })
        except requests.exceptions.SSLError:
            return jsonify({
                'url': url_completa,
                'accesible': False,
                'error': 'Error de certificado SSL'
            })
        except Exception as e:
            return jsonify({
                'url': url_completa,
                'accesible': False,
                'error': str(e)
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@scan_bp.route('/api/reportes/enviar', methods=['POST'])
@limiter.limit(REPORT_SEND_LIMIT_HOURLY)
@limiter.limit(REPORT_SEND_LIMIT_INTERVAL)
def enviar_informe_por_correo():
    try:
        admin_id = session.get('admin_id')
        if not admin_id:
            return jsonify({'error': 'No autorizado'}), 401

        datos = request.get_json() or {}
        escaneo_id = datos.get('escaneo_id')
        if escaneo_id is not None:
            try:
                escaneo_id = int(escaneo_id)
            except (TypeError, ValueError):
                return jsonify({'error': 'El identificador de escaneo no es valido.'}), 400

        correo_destino = base_datos.obtener_correo_usuario(admin_id)
        if not correo_destino:
            return jsonify({'error': 'No se encontro un correo asociado al usuario actual.'}), 400

        reporte = base_datos.obtener_reporte_escaneo(
            admin_id, escaneo_id=escaneo_id)
        if not reporte:
            return jsonify({'error': 'No hay datos de escaneo para generar el informe.'}), 404

        resumen_pdf = _construir_resumen_pdf(reporte)

        html_reporte = render_template(
            'reporte_pdf.html',
            reporte=reporte,
            resumen=resumen_pdf,
        )
        pdf_bytes = html_a_pdf_bytes(html_reporte)

        asunto = f"Informe VulnShield - Escaneo #{reporte['escaneo_id']}"
        cuerpo = (
            'Adjunto encontraras el informe PDF generado con los resultados '
            'del escaneo solicitado.'
        )
        nombre_adjunto = f"informe_escaneo_{reporte['escaneo_id']}.pdf"

        enviar_correo_con_adjunto(
            destinatario=correo_destino,
            asunto=asunto,
            cuerpo_texto=cuerpo,
            nombre_adjunto=nombre_adjunto,
            adjunto_pdf=pdf_bytes,
        )

        return jsonify({
            'ok': True,
            'mensaje': f'Informe enviado correctamente a {correo_destino}.',
            'escaneo_id': reporte['escaneo_id'],
        })
    except PdfGenerationError as e:
        return jsonify({'error': str(e)}), 500
    except EmailDeliveryError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@scan_bp.route('/reportes/vista-previa', methods=['GET'])
def vista_previa_informe():
    if not session.get('admin_id'):
        return redirect(url_for('auth.inisesion'))
    admin_id = session.get('admin_id')

    escaneo_id = request.args.get('escaneo_id')
    from flask import make_response
    if escaneo_id is not None:
        try:
            escaneo_id = int(escaneo_id)
        except (TypeError, ValueError):
            response = render_template(
                'reporte_resultados.html',
                reporte=None,
                error_reporte='El identificador de escaneo no es valido.',
                modo_pdf=False,
            )
            resp = make_response(response)
            resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            resp.headers['Pragma'] = 'no-cache'
            resp.headers['Expires'] = '0'
            return resp, 400

    reporte = base_datos.obtener_reporte_escaneo(
        admin_id, escaneo_id=escaneo_id)
    if not reporte:
        response = render_template(
            'reporte_resultados.html',
            reporte=None,
            error_reporte='No hay datos de escaneo disponibles para mostrar la vista previa.',
            modo_pdf=False,
        )
        resp = make_response(response)
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp, 404

    response = render_template(
        'reporte_resultados.html',
        reporte=reporte,
        error_reporte=None,
        modo_pdf=False,
    )
    resp = make_response(response)
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@scan_bp.route('/escaneos')
def escaneos():
    if not session.get('admin_id'):
        return redirect(url_for('auth.inisesion'))
    usuario = session.get('admin_usuario', 'Usuario')
    return render_template('escaneos.html', usuario=usuario)


# ============================================
# RUTA PRINCIPAL - SIEMPRE MUESTRA LANDINGPAGE.HTML
# ============================================
@scan_bp.route('/', methods=['GET'])
def root_redirect():
    """Página principal pública - siempre muestra landingpage.html"""
    return render_template('landingpage.html')


@scan_bp.route('/dashboard', methods=['GET'])
def dashboard():
    if not session.get('admin_id'):
        return redirect(url_for('auth.inisesion'))
    admin_id = session.get('admin_id')
    usuario = session.get('admin_usuario', 'Usuario')
    metricas_usuario = base_datos.obtener_metricas_resumen_usuario(admin_id)
    return render_template(
        'dashboard.html',
        usuario=usuario,
        total_hallazgos_bd=0,
        total_criticas_bd=0,
        total_escaneos_bd=metricas_usuario.get('total_escaneos', 0),
        escaneos_hoy_bd=metricas_usuario.get('escaneos_hoy', 0),
    )


# ============================================
# NUEVA RUTA PARA CONFIGURACIÓN
# ============================================
@scan_bp.route('/configuracion')
def configuracion():
    if not session.get('admin_id'):
        return redirect(url_for('auth.inisesion'))
    usuario = session.get('admin_usuario', 'Usuario')
    return render_template('configuracion.html', usuario=usuario)
