from flask import Flask, jsonify, request, render_template, redirect, session, url_for
import os
import math
import base_datos

from app.routes.scan_routes import scan_bp
from app.routes.admin_routes import admin_bp
from app.routes.auth_routes import auth_bp
from app.extensions import limiter


def create_app():
    app = Flask(__name__, template_folder='../templates')
    app.config['SECRET_KEY'] = os.getenv(
        'FLASK_SECRET_KEY', 'vulnshield-dev-secret-key')
    app.config['RATELIMIT_STORAGE_URI'] = os.getenv(
        'RATE_LIMIT_STORAGE_URI', 'memory://')
    app.config['RATELIMIT_ENABLED'] = os.getenv(
        'RATE_LIMIT_ENABLED', 'true').lower() in ('1', 'true', 'yes')

    limiter.init_app(app)

    def _obtener_retry_after_segundos(error):
        retry_after = getattr(error, 'retry_after', None)
        if retry_after is not None:
            try:
                return max(1, int(math.ceil(float(retry_after))))
            except Exception:
                return None
        return None

    def _mensaje_limite_amigable(error, path=''):
        segundos = _obtener_retry_after_segundos(error)

        if path.startswith('/api/reportes/enviar'):
            if segundos is not None:
                return f'Ya generaste un PDF hace poco. Espera {segundos} segundos para volver a enviarlo.'
            return 'Ya generaste un PDF hace poco. Espera un momento para volver a enviarlo.'

        if segundos is not None:
            return (
                'Has realizado varios escaneos en poco tiempo. '
                f'Espera {segundos} segundos para volver a intentarlo.'
            )

        return (
            'Has realizado varios escaneos en poco tiempo. '
            'Espera un momento y vuelve a intentarlo.'
        )

    @app.errorhandler(429)
    def manejar_rate_limit(e):
        path = request.path or ''
        mensaje = _mensaje_limite_amigable(e, path=path)
        retry_after_segundos = _obtener_retry_after_segundos(e)

        if request.path.startswith('/api/'):
            payload = {'error': mensaje}
            if retry_after_segundos is not None:
                payload['retry_after'] = retry_after_segundos
            return jsonify(payload), 429

        return render_template(
            'dashboard.html',
            resultados=[{
                'tipo': 'Limite de escaneo',
                'severidad': 'Media',
                'descripcion': mensaje,
            }],
            url_escaneada='',
            protocolo_usado='No especificado',
        ), 429

    rutas_protegidas_prefijos = (
        '/dashboard',
        '/escaneos',
        '/configuracion',
        '/admin',
        '/admin_home',
        '/reportes',
        '/api/',
    )

    rutas_admin_prefijos = (
        '/admin',
        '/admin_home',
        '/api/dashboard-data',
        '/api/administradores',
    )

    rutas_usuario_prefijos = (
        '/dashboard',
        '/escaneos',
        '/configuracion',
        '/reportes',
        '/api/escanear',
        '/api/historial-escaneos',
        '/api/verificar-url',
        '/api/reportes',
        '/api/usuario',
    )

    @app.before_request
    def proteger_rutas_sesion():
        path = request.path or ''

        # Permitir recursos publicos y de sesion
        if path.startswith('/static/'):
            return None
        if path in (
            '/',
            '/inisesion',
            '/recuperar-contrasena',
            '/api/auth/login',
            '/api/auth/registro',
            '/api/auth/recuperar-contrasena',
            '/api/auth/recuperacion-estado',
            '/api/auth/restablecer-contrasena',
            '/logout',
        ):
            return None

        requiere_sesion = any(path.startswith(prefijo)
                              for prefijo in rutas_protegidas_prefijos)
        if not requiere_sesion:
            return None

        if not session.get('admin_id'):
            if path.startswith('/api/'):
                return jsonify({'error': 'No autorizado'}), 401
            return redirect(url_for('auth.inisesion'))

        es_admin = bool(session.get('admin_inrol'))
        es_ruta_admin = any(path.startswith(prefijo)
                            for prefijo in rutas_admin_prefijos)
        es_ruta_usuario = any(path.startswith(prefijo)
                              for prefijo in rutas_usuario_prefijos)

        if es_ruta_admin and not es_admin:
            if path.startswith('/api/'):
                return jsonify({'error': 'Prohibido: ruta solo para administradores'}), 403
            return redirect(url_for('scan.dashboard'))

        if es_ruta_usuario and es_admin:
            if path.startswith('/api/'):
                return jsonify({'error': 'Prohibido: ruta solo para usuarios'}), 403
            return redirect(url_for('admin.admin_home'))

        return None

    @app.after_request
    def deshabilitar_cache_en_rutas_protegidas(response):
        path = request.path or ''
        rutas_no_cache = (
            '/dashboard',
            '/escaneos',
            '/configuracion',
            '/admin',
            '/admin_home',
            '/reportes',
            '/api/',
            '/logout',
        )

        if any(path.startswith(prefijo) for prefijo in rutas_no_cache):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

        return response

    try:
        base_datos.inicializar_db()
    except Exception as e:
        print(
            f"[WARN] No se pudo inicializar la base de datos al arrancar: {e}")
        print("[WARN] La interfaz web seguira disponible, pero algunas funciones pueden fallar hasta corregir la BD.")

    app.register_blueprint(scan_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(auth_bp)

    return app
