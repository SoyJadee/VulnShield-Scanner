from flask import Blueprint, jsonify, redirect, request, session, url_for, render_template
from werkzeug.security import check_password_hash, generate_password_hash
import random
import time
import re

import base_datos
from app.services.email_service import EmailDeliveryError, enviar_correo
from app.utils.security import sanitizar_entrada, validar_contrasena_fuerte, validar_email, validar_usuario

auth_bp = Blueprint('auth', __name__)

USUARIO_MIN_LEN = 6
USUARIO_MAX_LEN = 20
EMAIL_MIN_LEN = 6
EMAIL_MAX_LEN = 100
CODIGO_RECUPERACION_LEN = 6
CODIGO_RECUPERACION_TTL_SEGUNDOS = 900
CODIGO_RECUPERACION_COOLDOWN_SEGUNDOS = 60


def _normalizar_correo(valor):
    correo = sanitizar_entrada(str(valor or '').strip().lower())
    return correo.replace(' ', '')


def _sanitizar_codigo(valor):
    codigo = sanitizar_entrada(str(valor or '').strip())
    # Solo permitir digitos para el codigo de recuperacion.
    return re.sub(r'\D', '', codigo)


def _censurar_correo(correo):
    correo = str(correo or '').strip()
    if '@' not in correo:
        return '***@***'

    local, dominio = correo.split('@', 1)
    local_visible = local[:2] if len(local) >= 2 else local[:1]
    local_mascara = local_visible + \
        ('*' * max(2, len(local) - len(local_visible)))

    if '.' in dominio:
        nombre_dom, resto = dominio.split('.', 1)
        dom_visible = nombre_dom[:1]
        dom_mascara = dom_visible + ('*' * max(2, len(nombre_dom) - 1))
        return f'{local_mascara}@{dom_mascara}.{resto}'

    dom_visible = dominio[:1]
    dom_mascara = dom_visible + ('*' * max(2, len(dominio) - 1))
    return f'{local_mascara}@{dom_mascara}'


def _limpiar_estado_recuperacion():
    session.pop('recuperacion_codigo', None)
    session.pop('recuperacion_usuario_id', None)
    session.pop('recuperacion_expira', None)
    session.pop('recuperacion_correo', None)
    session.pop('recuperacion_ultimo_envio', None)


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


@auth_bp.route('/recuperar-contrasena', methods=['GET'])
def recuperar_contrasena_view():
    return render_template('recuperar_contrasena.html')


@auth_bp.route('/api/auth/recuperar-contrasena', methods=['POST'])
def api_recuperar_contrasena():
    datos = request.get_json() or {}
    correo = _normalizar_correo(datos.get('correo', ''))
    ahora = int(time.time())

    ultimo_envio = int(session.get('recuperacion_ultimo_envio', 0) or 0)
    if ultimo_envio:
        transcurrido = ahora - ultimo_envio
        if transcurrido < CODIGO_RECUPERACION_COOLDOWN_SEGUNDOS:
            restante = CODIGO_RECUPERACION_COOLDOWN_SEGUNDOS - transcurrido
            return jsonify({
                'error': f'Espera {restante} segundos antes de solicitar otro código',
                'retry_after': restante,
            }), 429

    if not correo:
        return jsonify({'error': 'El correo es obligatorio'}), 400

    if len(correo) < EMAIL_MIN_LEN or len(correo) > EMAIL_MAX_LEN:
        return jsonify({'error': f'El correo debe tener entre {EMAIL_MIN_LEN} y {EMAIL_MAX_LEN} caracteres'}), 400

    if not validar_email(correo):
        return jsonify({'error': 'Formato de correo inválido'}), 400

    usuario = base_datos.obtener_administrador_por_correo(correo)
    if not usuario:
        return jsonify({'error': 'No existe una cuenta con ese correo'}), 404

    if usuario.get('activo', False):
        return jsonify({'error': 'La recuperación de contraseña no está habilitada para cuentas administradoras'}), 403

    codigo = ''.join(random.choices('0123456789', k=CODIGO_RECUPERACION_LEN))
    session['recuperacion_codigo'] = codigo
    session['recuperacion_usuario_id'] = int(usuario['id'])
    session['recuperacion_expira'] = int(
        time.time()) + CODIGO_RECUPERACION_TTL_SEGUNDOS
    session['recuperacion_correo'] = correo
    session['recuperacion_ultimo_envio'] = ahora

    correo_censurado = _censurar_correo(correo)

    warning = None
    try:
        enviar_correo(
            destinatario=correo,
            asunto='Codigo de recuperacion - VulnShield',
            cuerpo_texto=(
                'Solicitaste recuperar tu contraseña.\n\n'
                f'Tu codigo de recuperacion es: {codigo}\n\n'
                'Este codigo vence en 15 minutos.'
            ),
        )
    except EmailDeliveryError as e:
        warning = str(e)

    return jsonify({
        'ok': True,
        'mensaje': f'Se ha enviado un codigo al correo {correo_censurado}',
        'correo_censurado': correo_censurado,
        'cooldown_segundos': CODIGO_RECUPERACION_COOLDOWN_SEGUNDOS,
        'warning': warning,
    })


@auth_bp.route('/api/auth/recuperacion-estado', methods=['GET'])
def api_recuperacion_estado():
    ahora = int(time.time())
    ultimo_envio = int(session.get('recuperacion_ultimo_envio', 0) or 0)
    cooldown_restante = 0
    if ultimo_envio:
        cooldown_restante = max(
            0,
            CODIGO_RECUPERACION_COOLDOWN_SEGUNDOS - (ahora - ultimo_envio)
        )

    codigo = str(session.get('recuperacion_codigo', '')).strip()
    correo = _normalizar_correo(session.get('recuperacion_correo', ''))
    expira = int(session.get('recuperacion_expira', 0) or 0)
    codigo_pendiente = bool(codigo and correo and expira > ahora)

    return jsonify({
        'ok': True,
        'cooldown_restante': cooldown_restante,
        'codigo_pendiente': codigo_pendiente,
        'correo_censurado': _censurar_correo(correo) if codigo_pendiente else None,
    })


@auth_bp.route('/api/auth/restablecer-contrasena', methods=['POST'])
def api_restablecer_contrasena():
    datos = request.get_json() or {}
    correo = _normalizar_correo(datos.get('correo', ''))
    codigo = _sanitizar_codigo(datos.get('codigo', ''))
    contrasena_nueva = str(datos.get('contrasena_nueva', '')).strip()

    if not correo or not codigo or not contrasena_nueva:
        return jsonify({'error': 'Correo, código y nueva contraseña son obligatorios'}), 400

    if not validar_email(correo):
        return jsonify({'error': 'Formato de correo inválido'}), 400

    usuario = base_datos.obtener_administrador_por_correo(correo)
    if not usuario:
        return jsonify({'error': 'No existe una cuenta con ese correo'}), 404

    if usuario.get('activo', False):
        return jsonify({'error': 'No se permite restablecer contraseña de cuentas administradoras'}), 403

    codigo_guardado = str(session.get('recuperacion_codigo', '')).strip()
    usuario_id_guardado = session.get('recuperacion_usuario_id')
    expira = int(session.get('recuperacion_expira', 0) or 0)
    correo_guardado = str(session.get(
        'recuperacion_correo', '')).strip().lower()

    if not codigo_guardado or not usuario_id_guardado or not expira or not correo_guardado:
        return jsonify({'error': 'Primero debes solicitar un código de recuperación'}), 400

    if int(time.time()) > expira:
        _limpiar_estado_recuperacion()
        return jsonify({'error': 'El código de recuperación expiró. Solicita uno nuevo'}), 400

    if int(usuario['id']) != int(usuario_id_guardado) or correo != correo_guardado:
        return jsonify({'error': 'El código no corresponde al correo indicado'}), 400

    if codigo != codigo_guardado:
        return jsonify({'error': 'El código de recuperación es incorrecto'}), 400

    if not validar_contrasena_fuerte(contrasena_nueva):
        return jsonify({'error': 'La contraseña debe tener entre 8 y 20 caracteres, mínimo una mayúscula, mínimo una minúscula y mínimo un carácter especial'}), 400

    nuevo_hash = generate_password_hash(contrasena_nueva)
    actualizado = base_datos.actualizar_contrasena(
        int(usuario['id']), nuevo_hash)
    if not actualizado:
        return jsonify({'error': 'No se pudo restablecer la contraseña'}), 500

    _limpiar_estado_recuperacion()
    return jsonify({'ok': True, 'mensaje': 'Contraseña restablecida correctamente. Ya puedes iniciar sesión'})


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

    if len(email) > EMAIL_MAX_LEN:
        return jsonify({'error': f'El correo no puede exceder {EMAIL_MAX_LEN} caracteres'}), 400

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
    campo = str(datos.get('campo', '')).strip().lower()  # 'usuario' o 'email'
    valor = sanitizar_entrada(str(datos.get('valor', '')).strip())
    campos_permitidos = {'usuario', 'email'}

    if campo not in campos_permitidos:
        return jsonify({'error': 'Campo inválido. Solo se permite actualizar usuario o email'}), 400

    if not valor:
        return jsonify({'error': 'Campo y valor son requeridos'}), 400

    # Validar según el campo
    if campo == 'usuario':
        # Validar formato de usuario
        if len(valor) < USUARIO_MIN_LEN or len(valor) > USUARIO_MAX_LEN:
            return jsonify({'error': f'El usuario debe tener entre {USUARIO_MIN_LEN} y {USUARIO_MAX_LEN} caracteres'}), 400
        if not validar_usuario(valor):
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
        if len(valor) < EMAIL_MIN_LEN or len(valor) > EMAIL_MAX_LEN:
            return jsonify({'error': f'El correo debe tener entre {EMAIL_MIN_LEN} y {EMAIL_MAX_LEN} caracteres'}), 400
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
    contrasena_actual = str(datos.get('contrasena_actual', '')).strip()
    contrasena_nueva = str(datos.get('contrasena_nueva', '')).strip()

    if not contrasena_actual or not contrasena_nueva:
        return jsonify({'error': 'Todos los campos son requeridos'}), 400

    # Verificar contraseña actual
    usuario = base_datos.obtener_usuario_por_id(usuario_id)
    if not usuario:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    if usuario.get('activo', False):
        return jsonify({'error': 'Las cuentas administradoras no pueden cambiar contraseña desde esta opción'}), 403

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
