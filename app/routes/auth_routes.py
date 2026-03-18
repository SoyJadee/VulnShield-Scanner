from flask import Blueprint, jsonify, redirect, request, session, url_for, render_template
from werkzeug.security import check_password_hash, generate_password_hash

import base_datos
from app.utils.security import validar_contrasena_fuerte, validar_email

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/inisesion')
def inisesion():
    return render_template('inisesion.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.inisesion'))


@auth_bp.route('/api/auth/registro', methods=['POST'])
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


@auth_bp.route('/api/auth/login', methods=['POST'])
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

    return jsonify({'ok': True, 'redirect': url_for('admin.admin')})
