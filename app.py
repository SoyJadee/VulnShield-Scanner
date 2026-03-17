from flask import Flask, render_template, request, jsonify
import motor_escaneo
import base_datos
from urllib.parse import urlparse

app = Flask(__name__)
base_datos.inicializar_db()


def normalizar_url(protocolo_seleccionado, url_ingresada):
    """Construye la URL respetando SIEMPRE el protocolo seleccionado"""
    url_ingresada = url_ingresada.strip()
    
    if url_ingresada.startswith(('http://', 'https://')):
        pos_protocolo = url_ingresada.find('://') + 3
        url_sin_protocolo = url_ingresada[pos_protocolo:]
        print(f"🔄 Protocolo detectado, eliminado: {url_ingresada} -> {url_sin_protocolo}")
    else:
        url_sin_protocolo = url_ingresada
    
    url_final = f"{protocolo_seleccionado}{url_sin_protocolo}"
    print(f"✅ URL normalizada: {url_final}")
    
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
        protocolo = request.form.get('protocolo', 'https://')
        url_ingresada = request.form.get('url', '')
        
        url_objetivo = normalizar_url(protocolo, url_ingresada)
        protocolo_usado = obtener_protocolo_desde_url(url_objetivo)
        
        print(f"🔍 Escaneando: {url_objetivo}")
        
        # Ejecutar escaneo
        resultados = motor_escaneo.iniciar_escaneo_completo(url_objetivo)
        
        # Guardar hallazgos usando la nueva función
        for res in resultados:
            if res['tipo'] != "Ninguna detectada":
                # Extraer tipo limpio (sin el payload)
                tipo_vuln = res['tipo'].split(' - ')[0].split('(')[0].strip()
                if 'SQL' in tipo_vuln:
                    tipo_limpio = 'SQL Injection'
                elif 'XSS' in tipo_vuln:
                    tipo_limpio = 'XSS'
                else:
                    tipo_limpio = tipo_vuln
                
                base_datos.guardar_hallazgo(url_objetivo, tipo_limpio)
    
    return render_template(
        'dashboard.html', 
        resultados=resultados, 
        url_escaneada=url_objetivo,
        protocolo_usado=protocolo_usado
    )


# NUEVO ENDPOINT: Obtener datos para el dashboard admin
@app.route('/api/dashboard-data')
def api_dashboard_data():
    """Endpoint que devuelve los datos para el panel de administración"""
    datos = base_datos.obtener_datos_dashboard()
    if datos:
        return jsonify(datos)
    return jsonify({'error': 'No se pudieron obtener los datos'}), 500


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
        
        url_completa = normalizar_url(protocolo, url_ingresada)
        protocolo_usado = obtener_protocolo_desde_url(url_completa)
        
        print(f"📡 API - Escaneando: {url_completa}")
        
        resultados = motor_escaneo.iniciar_escaneo_completo(url_completa)
        
        for res in resultados:
            if res['tipo'] != "Ninguna detectada":
                if 'SQL' in res['tipo']:
                    tipo_limpio = 'SQL Injection'
                elif 'XSS' in res['tipo']:
                    tipo_limpio = 'XSS'
                else:
                    tipo_limpio = res['tipo'].split(' - ')[0]
                
                base_datos.guardar_hallazgo(url_completa, tipo_limpio)
        
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