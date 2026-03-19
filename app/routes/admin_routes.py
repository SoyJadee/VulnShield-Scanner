from flask import Blueprint, jsonify, request, render_template, redirect, session, url_for
from werkzeug.security import generate_password_hash
import re

import base_datos
from app.utils.security import validar_contrasena_fuerte, validar_email

admin_bp = Blueprint('admin', __name__)

ADMIN_PRINCIPAL = 'admin'


@admin_bp.route('/admin_home')
def admin_home():
    if not session.get('admin_id'):
        return redirect(url_for('auth.inisesion'))
    username = session.get('admin_usuario', 'Admin')
    response = render_template('admin.html', username=username)
    from flask import make_response
    resp = make_response(response)
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@admin_bp.route('/admin')
def admin():
    if not session.get('admin_id'):
        return redirect(url_for('auth.inisesion'))
    username = session.get('admin_usuario', 'Admin')
    response = render_template('admin.html', username=username)
    from flask import make_response
    resp = make_response(response)
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@admin_bp.route('/api/dashboard-data')
def api_dashboard_data():
    datos = base_datos.obtener_datos_dashboard()
    if datos:
        return jsonify(datos)
    return jsonify({'error': 'No se pudieron obtener los datos'}), 500


# ============================================
# ENDPOINTS PARA GESTIÓN DE ADMINISTRADORES
# ============================================

@admin_bp.route('/api/administradores', methods=['GET'])
def api_listar_administradores():
    """Lista todos los administradores (solo para admin principal)"""
    if not session.get('admin_id'):
        return jsonify({'error': 'No autorizado'}), 401

    # Verificar que el usuario actual es admin principal
    solicitante = session.get('admin_usuario', '').strip().lower()
    if solicitante != ADMIN_PRINCIPAL:
        return jsonify({'error': 'Solo el administrador principal puede ver la lista de administradores'}), 403

    admins = base_datos.listar_administradores()
    if admins is None:
        return jsonify({'error': 'No se pudo obtener la lista de administradores'}), 500

    return jsonify({'administradores': admins, 'admin_principal': ADMIN_PRINCIPAL})


@admin_bp.route('/api/administradores', methods=['POST'])
def api_crear_administrador():
    """Crea un nuevo administrador (solo para admin principal)"""
    if not session.get('admin_id'):
        return jsonify({'error': 'No autorizado'}), 401

    # Verificar que el usuario actual es admin principal
    solicitante = session.get('admin_usuario', '').strip().lower()
    if solicitante != ADMIN_PRINCIPAL:
        return jsonify({'error': 'Solo el administrador principal puede agregar administradores'}), 403

    datos = request.get_json() or {}

    usuario = str(datos.get('usuario', '')).strip()
    email = str(datos.get('email', '')).strip().lower().replace(' ', '')
    contrasena = str(datos.get('contrasena', '')).strip()

    # Validaciones
    if not usuario or not email or not contrasena:
        return jsonify({'error': 'Usuario, correo y contraseña son obligatorios'}), 400

    # Validar formato de email
    if not validar_email(email):
        return jsonify({'error': 'Formato de correo inválido'}), 400

    # Validar longitud del email
    if len(email) > 100:
        return jsonify({'error': 'El correo no puede exceder 100 caracteres'}), 400

    # Validar usuario (entre 6 y 20 caracteres, solo letras, números, _ y .)
    if len(usuario) < 6 or len(usuario) > 20:
        return jsonify({'error': 'El usuario debe tener entre 6 y 20 caracteres'}), 400
    if not re.match(r'^[a-zA-Z0-9_.]+$', usuario):
        return jsonify({'error': 'El usuario solo puede contener letras, números, guiones bajos (_) y puntos (.)'}), 400

    # Validar contraseña fuerte
    if not validar_contrasena_fuerte(contrasena):
        return jsonify({'error': 'La contraseña debe tener entre 8 y 20 caracteres, incluir mayúscula, minúscula y un carácter especial'}), 400

    # Verificar que el email no exista
    if base_datos.existe_email(email):
        return jsonify({'error': 'Ese correo ya está siendo utilizado por otro usuario o administrador'}), 400

    # Verificar que el usuario no exista
    if base_datos.existe_usuario(usuario):
        return jsonify({'error': 'El nombre de usuario ya está registrado'}), 400

    # Crear administrador
    resultado = base_datos.crear_administrador(
        usuario=usuario,
        contrasena_hash=generate_password_hash(contrasena),
        email=email,
        es_admin=True
    )

    if not resultado.get('ok'):
        return jsonify({'error': resultado.get('error', 'No se pudo crear el administrador')}), 400

    return jsonify({'ok': True, 'id': resultado.get('id'), 'mensaje': 'Administrador creado correctamente'})


@admin_bp.route('/api/administradores/<int:admin_id>', methods=['DELETE'])
def api_eliminar_administrador(admin_id):
    """Elimina un administrador (solo para admin principal)"""
    if not session.get('admin_id'):
        return jsonify({'error': 'No autorizado'}), 401

    # Verificar que el usuario actual es admin principal
    solicitante = session.get('admin_usuario', '').strip().lower()
    if solicitante != ADMIN_PRINCIPAL:
        return jsonify({'error': 'Solo el administrador principal puede eliminar administradores'}), 403

    resultado = base_datos.eliminar_administrador(
        admin_id, admin_principal=ADMIN_PRINCIPAL)

    if not resultado.get('ok'):
        return jsonify({'error': resultado.get('error', 'No se pudo eliminar el administrador')}), 400

    return jsonify({'ok': True, 'mensaje': 'Administrador eliminado correctamente'})
