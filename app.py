from flask import Flask, render_template, request, jsonify
import motor_escaneo
import base_datos
from urllib.parse import urlparse

app = Flask(__name__)
base_datos.inicializar_db()


def normalizar_url(protocolo_seleccionado, url_ingresada):
    """
    Construye la URL respetando SIEMPRE el protocolo seleccionado por el usuario.
    Si el usuario incluyó http:// o https:// en la URL, se ELIMINA y se usa el seleccionado.
    
    Ejemplos:
    - protocolo='https://', url_ingresada='ejemplo.com' -> 'https://ejemplo.com'
    - protocolo='https://', url_ingresada='http://ejemplo.com' -> 'https://ejemplo.com'
    - protocolo='http://', url_ingresada='https://ejemplo.com' -> 'http://ejemplo.com'
    """
    # Limpiar espacios
    url_ingresada = url_ingresada.strip()
    
    # PASO 1: Eliminar cualquier protocolo que el usuario haya escrito
    # Quitar http:// o https:// del inicio si existen
    if url_ingresada.startswith(('http://', 'https://')):
        # Encontrar dónde termina el protocolo (después de '://')
        pos_protocolo = url_ingresada.find('://') + 3
        url_sin_protocolo = url_ingresada[pos_protocolo:]
        print(f"🔄 Protocolo detectado en URL ingresada, eliminado: {url_ingresada} -> {url_sin_protocolo}")
    else:
        url_sin_protocolo = url_ingresada
    
    # PASO 2: Aplicar el protocolo seleccionado por el usuario
    url_final = f"{protocolo_seleccionado}{url_sin_protocolo}"
    
    print(f"✅ URL normalizada: {url_final} (usando protocolo seleccionado: {protocolo_seleccionado})")
    
    return url_final


def obtener_protocolo_desde_url(url):
    """Determina si una URL usa HTTP o HTTPS"""
    if url.startswith('https://'):
        return 'HTTPS'
    elif url.startswith('http://'):
        return 'HTTP'
    else:
        return 'No especificado'


@app.route('/', methods=['GET', 'POST'])
def dashboard():
    resultados = []
    url_objetivo = ""
    protocolo_usado = "No especificado"
    
    if request.method == 'POST':
        # Obtener datos del formulario
        protocolo = request.form.get('protocolo', 'https://')  # Por defecto HTTPS
        url_ingresada = request.form.get('url', '')
        
        # NUEVA: Limpiar cualquier protocolo que el usuario haya escrito
        # y aplicar el protocolo seleccionado
        url_objetivo = normalizar_url(protocolo, url_ingresada)
        protocolo_usado = obtener_protocolo_desde_url(url_objetivo)
        
        print(f"🔍 Escaneando: {url_objetivo} (Protocolo elegido: {protocolo}, Protocolo final: {protocolo_usado})")
        
        # Ejecutar escaneo
        resultados = motor_escaneo.iniciar_escaneo_completo(url_objetivo)
        
        # Guardar hallazgos
        for res in resultados:
            if res['tipo'] != "Ninguna detectada":
                base_datos.guardar_hallazgo(url_objetivo, res['tipo'])
    
    return render_template(
        'dashboard.html', 
        resultados=resultados, 
        url_escaneada=url_objetivo,
        protocolo_usado=protocolo_usado
    )


@app.route('/api/escanear', methods=['POST'])
def api_escanear():
    """Endpoint API para escaneos vía JavaScript"""
    try:
        datos = request.get_json()
        
        if not datos:
            return jsonify({'error': 'No se recibieron datos'}), 400
        
        protocolo = datos.get('protocolo', 'https://')
        url_ingresada = datos.get('url', '')
        
        if not url_ingresada:
            return jsonify({'error': 'URL no proporcionada'}), 400
        
        # Usar la misma función normalizadora
        url_completa = normalizar_url(protocolo, url_ingresada)
        protocolo_usado = obtener_protocolo_desde_url(url_completa)
        
        print(f"📡 API - Escaneando: {url_completa} (Protocolo: {protocolo_usado})")
        
        # Ejecutar escaneo
        resultados = motor_escaneo.iniciar_escaneo_completo(url_completa)
        
        # Guardar hallazgos
        for res in resultados:
            if res['tipo'] != "Ninguna detectada":
                base_datos.guardar_hallazgo(url_completa, res['tipo'])
        
        return jsonify({
            'url': url_completa,
            'protocolo': protocolo_usado,
            'resultados': resultados,
            'total_vulnerabilidades': len([r for r in resultados if r['tipo'] != "Ninguna detectada"])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/verificar-url', methods=['POST'])
def verificar_url():
    """Verifica si una URL es accesible antes de escanear"""
    try:
        datos = request.get_json()
        protocolo = datos.get('protocolo', 'https://')
        url_ingresada = datos.get('url', '')
        
        # Normalizar URL igual que en el escaneo
        url_completa = normalizar_url(protocolo, url_ingresada)
        
        try:
            import requests
            response = requests.get(url_completa, timeout=5, verify=True)
            accesible = response.status_code == 200
            return jsonify({
                'url': url_completa,
                'accesible': accesible,
                'status_code': response.status_code
            })
        except requests.exceptions.SSLError:
            return jsonify({
                'url': url_completa,
                'accesible': False,
                'error': 'Error de certificado SSL'
            })
        except Exception as e:
            return jsonify({
                'url': url_completa,
                'accesible': False,
                'error': str(e)
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin')
def admin():
    return render_template('admin.html')


@app.route('/inisesion')
def inisesion():
    return render_template('inisesion.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)