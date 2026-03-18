from flask import Blueprint, jsonify, redirect, request, session, url_for, render_template
from werkzeug.security import check_password_hash, generate_password_hash
import re

import base_datos
from app.services.email_service import EmailDeliveryError, enviar_correo
from app.utils.security import sanitizar_entrada, validar_contrasena_fuerte, validar_email, validar_usuario

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/inisesion')
def inisesion():
    from flask import make_response
    response = render_template('inisesion.html')
    resp = make_response(response)
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


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

    usuario = sanitizar_entrada(usuario)
    email = sanitizar_entrada(email)

    if not usuario or not email or not contrasena:
        return jsonify({'error': 'Usuario, correo y contraseña son obligatorios'}), 400

    if len(email) > 50:
        return jsonify({'error': 'El correo no puede exceder 50 caracteres'}), 400

    if len(usuario) < 6:
        return jsonify({'error': 'El usuario debe tener al menos 6 caracteres'}), 400

    if not validar_usuario(usuario):
        return jsonify({'error': 'El usuario solo puede contener letras, números, guiones bajos (_) y puntos (.)'}), 400

    if not validar_email(email):
        return jsonify({'error': 'Formato de correo inválido'}), 400

    if not validar_contrasena_fuerte(contrasena):
        return jsonify({'error': 'La contraseña debe tener entre 8 y 20 caracteres, incluir mayúscula, minúscula y un carácter especial'}), 400

    resultado = base_datos.crear_administrador(
        usuario=usuario,
        contrasena_hash=generate_password_hash(contrasena),
        email=email,
        es_admin=False,
    )

    if not resultado.get('ok'):
        return jsonify({'error': resultado.get('error', 'No se pudo registrar el usuario')}), 400

    try:
        enviar_correo(
            destinatario=email,
            asunto='Confirmación de registro - VulnShield',
            cuerpo_texto=(
                '¡Bienvenido a VulnShield!\n\n'
                'Tu cuenta ha sido creada correctamente. Ya puedes iniciar sesión '
                'en el sistema usando tus credenciales.\n\n'
                'Si no solicitaste este registro, ignora este mensaje.'
            ),
        )
        return jsonify({'ok': True, 'mensaje': 'Registro exitoso. Se envió un correo de confirmación.'})
    except EmailDeliveryError as e:
        return jsonify({
            'ok': True,
            'mensaje': 'Registro exitoso, pero no se pudo enviar el correo de confirmación.',
            'warning': str(e)
        })


@auth_bp.route('/api/auth/login', methods=['POST'])
def api_login():
    datos = request.get_json() or {}

    correo = str(datos.get('correo', '')).strip()
    contrasena = str(datos.get('contrasena', '')).strip()

    print(f"📝 Intento de login - Correo: {correo}")

    if not correo or not contrasena:
        return jsonify({'error': 'Correo y contraseña son obligatorios'}), 400

    admin = base_datos.obtener_administrador_por_correo(correo)
    print(f"🔍 Admin encontrado: {admin}")

    if not admin:
        return jsonify({'error': 'Credenciales inválidas'}), 401

    if not check_password_hash(admin.get('contrasena_hash', ''), contrasena):
        print("❌ Contraseña incorrecta")
        return jsonify({'error': 'Credenciales inválidas'}), 401

    print("✅ Login exitoso")

    session['admin_id'] = admin['id']
    session['admin_usuario'] = admin['usuario']
    session['admin_email'] = admin['email']
    session['admin_inrol'] = admin.get('activo', False)

    if admin.get('activo', False):
        return jsonify({'ok': True, 'redirect': url_for('admin.admin_home')})
    else:
        return jsonify({'ok': True, 'redirect': url_for('scan.dashboard')})


# ============================================
# NUEVOS ENDPOINTS PARA CONFIGURACIÓN
# ============================================

@auth_bp.route('/api/usuario/actual', methods=['GET'])
def api_usuario_actual():
    """Obtiene los datos del usuario actualmente logueado"""
    if not session.get('admin_id'):
        return jsonify({'error': 'No autorizado'}), 401
    
    usuario_id = session.get('admin_id')
    usuario = base_datos.obtener_usuario_por_id(usuario_id)
    
    if not usuario:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    return jsonify({
        'id': usuario['id'],
        'usuario': usuario['usuario'],
        'email': usuario['email']
    })


@auth_bp.route('/api/usuario/actualizar', methods=['POST'])
def api_actualizar_usuario():
    """Actualiza los datos del usuario actual"""
    if not session.get('admin_id'):
        return jsonify({'error': 'No autorizado'}), 401
    
    datos = request.get_json() or {}
    usuario_id = session.get('admin_id')
    campo = datos.get('campo')  # 'usuario' o 'email'
    valor = datos.get('valor', '').strip()
    
    if not campo or not valor:
        return jsonify({'error': 'Campo y valor son requeridos'}), 400
    
    # Validar según el campo
    if campo == 'usuario':
        # Validar formato de usuario
        if len(valor) < 6 or len(valor) > 20:
            return jsonify({'error': 'El usuario debe tener entre 6 y 20 caracteres'}), 400
        if not re.match(r'^[a-zA-Z0-9_.]+$', valor):
            return jsonify({'error': 'El usuario solo puede contener letras, números, guiones bajos (_) y puntos (.)'}), 400
        
        # Verificar si ya existe otro usuario con ese nombre
        if base_datos.existe_usuario(valor, usuario_id):
            return jsonify({'error': 'El nombre de usuario ya está registrado por otra cuenta'}), 400
        
        # Actualizar
        resultado = base_datos.actualizar_usuario(usuario_id, campo, valor)
        if resultado:
            session['admin_usuario'] = valor
            return jsonify({'ok': True, 'mensaje': 'Nombre de usuario actualizado correctamente'})
    
    elif campo == 'email':
        # Validar formato de email
        if not validar_email(valor):
            return jsonify({'error': 'Formato de correo inválido'}), 400
        
        # Verificar si ya existe otro usuario con ese email
        if base_datos.existe_email(valor, usuario_id):
            return jsonify({'error': 'El correo ya está registrado por otra cuenta'}), 400
        
        # Actualizar
        resultado = base_datos.actualizar_usuario(usuario_id, campo, valor)
        if resultado:
            session['admin_email'] = valor
            return jsonify({'ok': True, 'mensaje': 'Correo actualizado correctamente'})
    
    return jsonify({'error': 'No se pudo actualizar'}), 500


@auth_bp.route('/api/usuario/cambiar-contrasena', methods=['POST'])
def api_cambiar_contrasena():
    """Cambia la contraseña del usuario"""
    if not session.get('admin_id'):
        return jsonify({'error': 'No autorizado'}), 401
    
    datos = request.get_json() or {}
    usuario_id = session.get('admin_id')
    contrasena_actual = datos.get('contrasena_actual', '').strip()
    contrasena_nueva = datos.get('contrasena_nueva', '').strip()
    
    if not contrasena_actual or not contrasena_nueva:
        return jsonify({'error': 'Todos los campos son requeridos'}), 400
    
    # Verificar contraseña actual
    usuario = base_datos.obtener_usuario_por_id(usuario_id)
    if not check_password_hash(usuario['contrasena_hash'], contrasena_actual):
        return jsonify({'error': 'La contraseña actual no es correcta'}), 400
    
    # Validar nueva contraseña
    if not validar_contrasena_fuerte(contrasena_nueva):
        return jsonify({'error': 'La contraseña debe tener entre 8 y 20 caracteres, incluir mayúscula, minúscula y un carácter especial'}), 400
    
    # Actualizar
    nuevo_hash = generate_password_hash(contrasena_nueva)
    resultado = base_datos.actualizar_contrasena(usuario_id, nuevo_hash)
    
    if resultado:
        return jsonify({'ok': True, 'mensaje': 'Contraseña actualizada correctamente'})
    
    return jsonify({'error': 'No se pudo actualizar la contraseña'}), 500