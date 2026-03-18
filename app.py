from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import motor_escaneo
import base_datos
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'vulnshield-dev-secret-key')
ADMIN_PRINCIPAL = 'admin'


def validar_contrasena_fuerte(valor):
    """Valida reglas: 8-20 chars, especial, mayuscula y minuscula"""
    if not valor:
        return False
    if len(valor) < 8 or len(valor) > 20:
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', valor):
        return False
    if not re.search(r'[a-z]', valor) or not re.search(r'[A-Z]', valor):
        return False
    return True


def validar_email(email):
    patron = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    return bool(re.match(patron, email or ''))


try:
    base_datos.inicializar_db()
except Exception as e:
    print(f"[WARN] No se pudo inicializar la base de datos al arrancar: {e}")
    print("[WARN] La interfaz web seguira disponible, pero algunas funciones pueden fallar hasta corregir la BD.")


def normalizar_url(protocolo_seleccionado, url_ingresada):
    """Construye la URL respetando SIEMPRE el protocolo seleccionado"""
    url_ingresada = url_ingresada.strip()
    
    if url_ingresada.startswith(('http://', 'https://')):
        pos_protocolo = url_ingresada.find('://') + 3
        url_sin_protocolo = url_ingresada[pos_protocolo:]
        print(f"🔄 Protocolo detectado, eliminado: {url_ingresada} -> {url_sin_protocolo}")
    else:
        url_sin_protocolo = url_ingresada
    
    url_final = f"{protocolo_seleccionado}{url_sin_protocolo}"
    print(f"✅ URL normalizada: {url_final}")
    
    return url_final


def obtener_protocolo_desde_url(url):
    """Determina si una URL usa HTTP o HTTPS"""
    if url.startswith('https://'):
        return 'HTTPS'
    elif url.startswith('http://'):
        return 'HTTP'
    else:
        return 'No especificado'


@app.route('/', methods=['GET', 'POST'])
def dashboard():
    resultados = []
    url_objetivo = ""
    protocolo_usado = "No especificado"
    
    if request.method == 'POST':
        protocolo = request.form.get('protocolo', 'https://')
        url_ingresada = request.form.get('url', '')
        
        url_objetivo = normalizar_url(protocolo, url_ingresada)
        protocolo_usado = obtener_protocolo_desde_url(url_objetivo)
        
        print(f"🔍 Escaneando: {url_objetivo}")
        
        # Ejecutar escaneo
        resultados = motor_escaneo.iniciar_escaneo_completo(url_objetivo)
        
        # Guardar hallazgos usando la nueva función
        for res in resultados:
            if res['tipo'] != "Ninguna detectada":
                # Extraer tipo limpio (sin el payload)
                tipo_vuln = res['tipo'].split(' - ')[0].split('(')[0].strip()
                if 'SQL' in tipo_vuln:
                    tipo_limpio = 'SQL Injection'
                elif 'XSS' in tipo_vuln:
                    tipo_limpio = 'XSS'
                else:
                    tipo_limpio = tipo_vuln
                
                base_datos.guardar_hallazgo(url_objetivo, tipo_limpio)
    
    return render_template(
        'dashboard.html', 
        resultados=resultados, 
        url_escaneada=url_objetivo,
        protocolo_usado=protocolo_usado
    )


# NUEVO ENDPOINT: Obtener datos para el dashboard admin
@app.route('/api/dashboard-data')
def api_dashboard_data():
    """Endpoint que devuelve los datos para el panel de administración"""
    datos = base_datos.obtener_datos_dashboard()
    if datos:
        return jsonify(datos)
    return jsonify({'error': 'No se pudieron obtener los datos'}), 500


@app.route('/api/administradores', methods=['GET'])
def api_listar_administradores():
    solicitante = request.args.get('solicitante', '').strip().lower()
    if solicitante != ADMIN_PRINCIPAL:
        return jsonify({'error': 'Solo el administrador principal puede gestionar administradores'}), 403

    admins = base_datos.listar_administradores()
    if admins is None:
        return jsonify({'error': 'No se pudo obtener la lista de administradores'}), 500

    return jsonify({'administradores': admins, 'admin_principal': ADMIN_PRINCIPAL})


@app.route('/api/administradores', methods=['POST'])
def api_crear_administrador():
    datos = request.get_json() or {}
    solicitante = str(datos.get('solicitante', '')).strip().lower()

    if solicitante != ADMIN_PRINCIPAL:
        return jsonify({'error': 'Solo el administrador principal puede agregar administradores'}), 403

    usuario = str(datos.get('usuario', '')).strip()
    email = str(datos.get('email', '')).strip() or None
    contrasena = str(datos.get('contrasena', '')).strip()

    if not usuario or not contrasena:
        return jsonify({'error': 'Usuario y contraseña son obligatorios'}), 400

    if email and len(email) > 50:
        return jsonify({'error': 'El correo no puede exceder 50 caracteres'}), 400

    if not validar_contrasena_fuerte(contrasena):
        return jsonify({'error': 'La contraseña debe tener entre 8 y 20 caracteres, incluir mayúscula, minúscula y un carácter especial'}), 400

    resultado = base_datos.crear_administrador(
        usuario=usuario,
        contrasena_hash=generate_password_hash(contrasena),
        email=email
    )

    if not resultado.get('ok'):
        return jsonify({'error': resultado.get('error', 'No se pudo crear el administrador')}), 400

    return jsonify({'ok': True, 'id': resultado.get('id')})


@app.route('/api/administradores/<int:admin_id>', methods=['DELETE'])
def api_eliminar_administrador(admin_id):
    solicitante = request.args.get('solicitante', '').strip().lower()
    if solicitante != ADMIN_PRINCIPAL:
        return jsonify({'error': 'Solo el administrador principal puede eliminar administradores'}), 403

    resultado = base_datos.eliminar_administrador(admin_id, admin_principal=ADMIN_PRINCIPAL)
    if not resultado.get('ok'):
        return jsonify({'error': resultado.get('error', 'No se pudo eliminar el administrador')}), 400

    return jsonify({'ok': True})


@app.route('/api/auth/registro', methods=['POST'])
def api_registro():
    datos = request.get_json() or {}

    usuario = str(datos.get('usuario', '')).strip()
    email = str(datos.get('email', '')).strip()
    contrasena = str(datos.get('contrasena', '')).strip()

    if not usuario or not email or not contrasena:
        return jsonify({'error': 'Usuario, correo y contraseña son obligatorios'}), 400

    if len(email) > 50:
        return jsonify({'error': 'El correo no puede exceder 50 caracteres'}), 400

    if len(usuario) < 3:
        return jsonify({'error': 'El usuario debe tener al menos 3 caracteres'}), 400

    if not validar_email(email):
        return jsonify({'error': 'Formato de correo inválido'}), 400

    if not validar_contrasena_fuerte(contrasena):
        return jsonify({'error': 'La contraseña debe tener entre 8 y 20 caracteres, incluir mayúscula, minúscula y un carácter especial'}), 400

    resultado = base_datos.crear_administrador(
        usuario=usuario,
        contrasena_hash=generate_password_hash(contrasena),
        email=email
    )

    if not resultado.get('ok'):
        return jsonify({'error': resultado.get('error', 'No se pudo registrar el usuario')}), 400

    return jsonify({'ok': True, 'mensaje': 'Registro exitoso'})


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    datos = request.get_json() or {}

    usuario = str(datos.get('usuario', '')).strip()
    contrasena = str(datos.get('contrasena', '')).strip()

    if not usuario or not contrasena:
        return jsonify({'error': 'Usuario y contraseña son obligatorios'}), 400

    if not validar_contrasena_fuerte(contrasena):
        return jsonify({'error': 'La contraseña debe cumplir con la política de seguridad'}), 400

    admin = base_datos.obtener_administrador_por_usuario(usuario)
    if not admin or not admin.get('activo'):
        return jsonify({'error': 'Credenciales inválidas'}), 401

    if not check_password_hash(admin.get('contrasena_hash', ''), contrasena):
        return jsonify({'error': 'Credenciales inválidas'}), 401

    base_datos.actualizar_ultimo_acceso(admin['id'])
    session['admin_id'] = admin['id']
    session['admin_usuario'] = admin['usuario']

    return jsonify({'ok': True, 'redirect': url_for('admin')})


@app.route('/api/escanear', methods=['POST'])
def api_escanear():
    """Endpoint API para escaneos vía JavaScript"""
    try:
        datos = request.get_json()
        
        if not datos:
            return jsonify({'error': 'No se recibieron datos'}), 400
        
        protocolo = datos.get('protocolo', 'https://')
        url_ingresada = datos.get('url', '')
        
        if not url_ingresada:
            return jsonify({'error': 'URL no proporcionada'}), 400
        
        url_completa = normalizar_url(protocolo, url_ingresada)
        protocolo_usado = obtener_protocolo_desde_url(url_completa)
        
        print(f"📡 API - Escaneando: {url_completa}")
        
        resultados = motor_escaneo.iniciar_escaneo_completo(url_completa)
        
        for res in resultados:
            if res['tipo'] != "Ninguna detectada":
                if 'SQL' in res['tipo']:
                    tipo_limpio = 'SQL Injection'
                elif 'XSS' in res['tipo']:
                    tipo_limpio = 'XSS'
                else:
                    tipo_limpio = res['tipo'].split(' - ')[0]
                
                base_datos.guardar_hallazgo(url_completa, tipo_limpio)
        
        return jsonify({
            'url': url_completa,
            'protocolo': protocolo_usado,
            'resultados': resultados,
            'total_vulnerabilidades': len([r for r in resultados if r['tipo'] != "Ninguna detectada"])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/verificar-url', methods=['POST'])
def verificar_url():
    """Verifica si una URL es accesible antes de escanear"""
    try:
        datos = request.get_json()
        protocolo = datos.get('protocolo', 'https://')
        url_ingresada = datos.get('url', '')
        
        url_completa = normalizar_url(protocolo, url_ingresada)
        
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


@app.route('/admin')
def admin():
    return render_template('admin.html')


@app.route('/logout')
def logout():
    return redirect(url_for('inisesion'))


@app.route('/inisesion')
def inisesion():
    return render_template('inisesion.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)