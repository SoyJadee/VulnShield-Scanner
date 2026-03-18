from io import BytesIO


class PdfGenerationError(Exception):
    pass


def html_a_pdf_bytes(html_content):
    """Convierte HTML renderizado a bytes de PDF."""
    try:
        from xhtml2pdf import pisa
    except Exception as exc:
        raise PdfGenerationError(
            "No se encontro xhtml2pdf. Instala dependencias para generar PDF."
        ) from exc

    buffer = BytesIO()
    resultado = pisa.CreatePDF(
        src=html_content,
        dest=buffer,
        encoding='utf-8',
    )

    if resultado.err:
        raise PdfGenerationError("No se pudo convertir el HTML a PDF.")

    return buffer.getvalue()
