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
    # host='0.0.0.0' es obligatorio para que Docker funcione
    app.run(debug=True, host='0.0.0.0', port=5000)
