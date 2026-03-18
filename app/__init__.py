from flask import Flask, jsonify, request, render_template
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

    def _mensaje_limite_amigable(error):
        retry_after = getattr(error, 'retry_after', None)
        if retry_after is not None:
            try:
                segundos = max(1, int(math.ceil(float(retry_after))))
                return (
                    'Has realizado varios escaneos en poco tiempo. '
                    f'Espera {segundos} segundos para volver a intentarlo.'
                )
            except Exception:
                pass

        return (
            'Has realizado varios escaneos en poco tiempo. '
            'Espera un momento y vuelve a intentarlo.'
        )

    @app.errorhandler(429)
    def manejar_rate_limit(e):
        mensaje = _mensaje_limite_amigable(e)
        if request.path.startswith('/api/'):
            return jsonify({'error': mensaje}), 429

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