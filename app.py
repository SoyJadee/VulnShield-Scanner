from flask import Flask, render_template, request
import motor_escaneo
import base_datos

app = Flask(__name__)
base_datos.inicializar_db()

@app.route('/', methods=['GET', 'POST'])
def dashboard():
    resultados = []
    url_objetivo = ""
    
    if request.method == 'POST':
        url_objetivo = request.form.get('url')
        resultados = motor_escaneo.iniciar_escaneo_completo(url_objetivo)
        
        for res in resultados:
            if res['tipo'] != "Ninguna detectada":
                base_datos.guardar_hallazgo(url_objetivo, res['tipo'])

    return render_template('dashboard.html', resultados=resultados, url_escaneada=url_objetivo)

if __name__ == '__main__':
    app.run(debug=True)
    # --- PÁGINA DE PRUEBA LOCAL (Para la defensa) ---
@app.route('/vulnerable', methods=['GET'])
def pagina_falsa():
    # Atrapamos lo que sea que el usuario ponga en el link después de ?id=
    parametro = request.args.get('id', '')
    
    # 1. Simulamos que la base de datos se rompe si recibe una comilla
    if "'" in parametro:
        return "Fatal error: You have an error in your SQL syntax near ''"
        
    # 2. Simulamos que refleja el código malicioso (XSS)
    if "<script>" in parametro:
        return f"<h1>Resultados para: {parametro}</h1>"
        
    return "Página de prueba normal. Todo seguro por aquí."