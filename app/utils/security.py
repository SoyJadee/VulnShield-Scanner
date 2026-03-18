import re


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


def validar_email(email):
    patron = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    return bool(re.match(patron, email or ''))
