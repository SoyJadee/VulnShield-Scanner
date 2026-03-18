from flask import Blueprint, jsonify, request, render_template
from werkzeug.security import generate_password_hash

import base_datos
from app.utils.security import validar_contrasena_fuerte

admin_bp = Blueprint('admin', __name__)

ADMIN_PRINCIPAL = 'admin'


@admin_bp.route('/admin')
def admin():
    return render_template('admin.html')


@admin_bp.route('/api/dashboard-data')
def api_dashboard_data():
    datos = base_datos.obtener_datos_dashboard()
    if datos:
        return jsonify(datos)
    return jsonify({'error': 'No se pudieron obtener los datos'}), 500


@admin_bp.route('/api/administradores', methods=['GET'])
def api_listar_administradores():
    solicitante = request.args.get('solicitante', '').strip().lower()
    if solicitante != ADMIN_PRINCIPAL:
        return jsonify({'error': 'Solo el administrador principal puede gestionar administradores'}), 403

    admins = base_datos.listar_administradores()
    if admins is None:
        return jsonify({'error': 'No se pudo obtener la lista de administradores'}), 500

    return jsonify({'administradores': admins, 'admin_principal': ADMIN_PRINCIPAL})


@admin_bp.route('/api/administradores', methods=['POST'])
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
        email=email,
        es_admin=True
    )

    if not resultado.get('ok'):
        return jsonify({'error': resultado.get('error', 'No se pudo crear el administrador')}), 400

    return jsonify({'ok': True, 'id': resultado.get('id')})


@admin_bp.route('/api/administradores/<int:admin_id>', methods=['DELETE'])
def api_eliminar_administrador(admin_id):
    solicitante = request.args.get('solicitante', '').strip().lower()
    if solicitante != ADMIN_PRINCIPAL:
        return jsonify({'error': 'Solo el administrador principal puede eliminar administradores'}), 403

    resultado = base_datos.eliminar_administrador(
        admin_id, admin_principal=ADMIN_PRINCIPAL)
    if not resultado.get('ok'):
        return jsonify({'error': resultado.get('error', 'No se pudo eliminar el administrador')}), 400

    return jsonify({'ok': True})
