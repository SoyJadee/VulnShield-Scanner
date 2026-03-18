import re
import html


def validar_email(email):
    """
    Valida el formato de un email usando una expresión regular básica.
    """
    if not email:
        return False
    # Expresión regular básica para validar email
    patron = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(patron, email) is not None


def validar_contrasena_fuerte(valor):
    if not valor:
        return False
    if len(valor) < 8 or len(valor) > 20:
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', valor):
        return False
    if not re.search(r'[a-z]', valor) or not re.search(r'[A-Z]', valor):
        return False
    return True


def validar_usuario(usuario):
    """
    Valida el nombre de usuario: longitud entre 6 y 20 caracteres,
    solo alfanuméricos, '_' y '.'.
    """
    if not usuario:
        return False
    if len(usuario) < 6 or len(usuario) > 20:
        return False
    # Solo permitir letras, números, '_' y '.'
    if not re.match(r'^[a-zA-Z0-9_.]+$', usuario):
        return False
    return True


def sanitizar_entrada(entrada):
    """
    Sanitiza una entrada de usuario: elimina caracteres peligrosos, escapa HTML y limita longitud.
    """
    if not entrada:
        return ''
    # Eliminar caracteres de control y peligrosos
    entrada = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', entrada)
    # Escapar HTML
    entrada = html.escape(entrada)
    # Limitar longitud a 255 caracteres para prevenir ataques de longitud
    return entrada[:255]
