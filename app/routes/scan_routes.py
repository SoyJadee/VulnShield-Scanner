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


def _hallazgos_para_bd(resultados):
    hallazgos = []
    for res in resultados:
        tipo = str(res.get('tipo', '')).strip()
        if not tipo or tipo == 'Ninguna detectada':
            continue
        hallazgos.append({
            'tipo': tipo,
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


@scan_bp.route('/api/escanear', methods=['POST'])
@limiter.limit(SCAN_LIMIT_HOURLY)
@limiter.limit(SCAN_LIMIT_INTERVAL)
def api_escanear():
    try:
        admin_id = session.get('admin_id', 1)
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

        hallazgos_bd = _hallazgos_para_bd(resultados)
        escaneo_id = base_datos.guardar_analisis_completo(
            url=url_completa,
            protocolo=protocolo_usado,
            administrador_id=admin_id,
            hallazgos_list=hallazgos_bd,
            tiempo_ejecucion=0,
        )

        metricas_dashboard = base_datos.obtener_metricas_resumen()

        return jsonify({
            'url': url_completa,
            'protocolo': protocolo_usado,
            'resultados': resultados_mostrables,
            'total_vulnerabilidades': len([r for r in resultados if r['tipo'] != "Ninguna detectada"]),
            'escaneo_id': escaneo_id,
            'total_hallazgos_bd': metricas_dashboard['total_hallazgos'],
            'total_criticas_bd': metricas_dashboard['vulnerabilidades_criticas'],
            'total_escaneos_bd': metricas_dashboard['total_escaneos'],
            'escaneos_hoy_bd': metricas_dashboard['escaneos_hoy'],
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
def enviar_informe_por_correo():
    try:
        admin_id = session.get('admin_id', 1)

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

        html_reporte = render_template(
            'reporte_resultados.html',
            reporte=reporte,
            error_reporte=None,
            modo_pdf=True,
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
    admin_id = session.get('admin_id', 1)

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
    usuario = session.get('admin_usuario', 'Usuario')
    return render_template('dashboard.html', usuario=usuario)


# ============================================
# NUEVA RUTA PARA CONFIGURACIÓN
# ============================================
@scan_bp.route('/configuracion')
def configuracion():
    if not session.get('admin_id'):
        return redirect(url_for('auth.inisesion'))
    usuario = session.get('admin_usuario', 'Usuario')
    return render_template('configuracion.html', usuario=usuario)