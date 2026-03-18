import re
import ipaddress
from urllib.parse import urlparse


URL_INPUT_MAX_LENGTH = 512
URL_FINAL_MAX_LENGTH = 2048
ALLOWED_PROTOCOLS = {'http://', 'https://'}


def sanitizar_url_entrada(url_ingresada):
    """Limpia espacios y caracteres de control peligrosos de la entrada."""
    valor = (url_ingresada or '').strip()
    valor = re.sub(r'[\x00-\x1F\x7F]', '', valor)
    return valor


def construir_y_validar_url(protocolo_seleccionado, url_ingresada):
    """Normaliza y valida una URL segun el protocolo permitido."""
    if protocolo_seleccionado not in ALLOWED_PROTOCOLS:
        return None, 'Protocolo invalido. Solo se permite HTTP o HTTPS.'

    valor = sanitizar_url_entrada(url_ingresada)
    if not valor:
        return None, 'Necesitas ingresar una URL.'

    if any(ch.isspace() for ch in valor):
        return None, 'Coloque una URL válida.'

    if len(valor) > URL_INPUT_MAX_LENGTH:
        return None, f'La URL no puede superar {URL_INPUT_MAX_LENGTH} caracteres.'

    if valor.startswith(('http://', 'https://')):
        pos_protocolo = valor.find('://') + 3
        url_sin_protocolo = valor[pos_protocolo:]
    else:
        url_sin_protocolo = valor

    if not url_sin_protocolo or url_sin_protocolo.startswith('/'):
        return None, 'Coloque una URL válida.'

    url_final = f"{protocolo_seleccionado}{url_sin_protocolo}"
    if len(url_final) > URL_FINAL_MAX_LENGTH:
        return None, f'La URL completa no puede superar {URL_FINAL_MAX_LENGTH} caracteres.'

    parsed = urlparse(url_final)
    if parsed.scheme not in ('http', 'https'):
        return None, 'Coloque una URL válida.'

    if not parsed.netloc or not parsed.hostname:
        return None, 'Coloque una URL válida.'

    host = parsed.hostname.lower()

    # Acepta IPs validas o dominios tipo ejemplo.com (con TLD).
    es_ip_valida = False
    try:
        ipaddress.ip_address(host)
        es_ip_valida = True
    except ValueError:
        es_ip_valida = False

    if not es_ip_valida:
        patron_dominio = r'^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
        if not re.match(patron_dominio, host):
            return None, 'Coloque una URL válida.'

    return url_final, None


def normalizar_url(protocolo_seleccionado, url_ingresada):
    url_ingresada = sanitizar_url_entrada(url_ingresada)

    if url_ingresada.startswith(('http://', 'https://')):
        pos_protocolo = url_ingresada.find('://') + 3
        url_sin_protocolo = url_ingresada[pos_protocolo:]
    else:
        url_sin_protocolo = url_ingresada

    return f"{protocolo_seleccionado}{url_sin_protocolo}"


def obtener_protocolo_desde_url(url):
    if url.startswith('https://'):
        return 'HTTPS'
    if url.startswith('http://'):
        return 'HTTP'
    return 'No especificado'
