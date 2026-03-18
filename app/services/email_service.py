import os
import smtplib
from email.message import EmailMessage


class EmailDeliveryError(Exception):
    pass


def _smtp_config_desde_entorno():
    host = os.getenv('SMTP_HOST', '').strip()
    port = int(os.getenv('SMTP_PORT', '587'))
    remitente = os.getenv('SMTP_FROM', '').strip()
    user = os.getenv('SMTP_USER', '').strip() or remitente
    password = os.getenv('SMTP_PASSWORD', '').strip(
    ) or os.getenv('SMTP_PASS', '').strip()
    usar_tls = os.getenv('SMTP_USE_TLS', 'true').strip(
    ).lower() in ('1', 'true', 'yes')

    if not host or not remitente:
        raise EmailDeliveryError(
            'Configura SMTP_HOST y SMTP_FROM para enviar correos.')

    # Proveedores como Gmail requieren autenticacion obligatoria.
    if 'gmail.com' in host and (not user or not password):
        raise EmailDeliveryError(
            'Configura SMTP_USER y SMTP_PASSWORD (clave de aplicacion de Gmail) para autenticar el envio.'
        )

    return {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'sender': remitente,
        'use_tls': usar_tls,
    }


def enviar_correo_con_adjunto(destinatario, asunto, cuerpo_texto, nombre_adjunto, adjunto_pdf):
    """Envia un correo con PDF adjunto usando SMTP."""
    config = _smtp_config_desde_entorno()

    mensaje = EmailMessage()
    mensaje['Subject'] = asunto
    mensaje['From'] = config['sender']
    mensaje['To'] = destinatario
    mensaje.set_content(cuerpo_texto)
    mensaje.add_attachment(
        adjunto_pdf,
        maintype='application',
        subtype='pdf',
        filename=nombre_adjunto,
    )

    try:
        with smtplib.SMTP(config['host'], config['port'], timeout=20) as smtp:
            if config['use_tls']:
                smtp.starttls()
            if config['user'] and config['password']:
                smtp.login(config['user'], config['password'])
            smtp.send_message(mensaje)
    except Exception as exc:
        raise EmailDeliveryError(
            f'No se pudo enviar el correo: {exc}') from exc
