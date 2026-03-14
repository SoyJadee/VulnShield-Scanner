from flask import Flask, request

app_victima = Flask(__name__)

@app_victima.route('/buscar', methods=['GET'])
def buscar():
    parametro = request.args.get('q', '')
    
    # 1. Trampa para SQL Injection
    if "'" in parametro:
        return "Fatal error: You have an error in your SQL syntax near ''"
        
    # 2. Trampa para XSS
    if "<script>" in parametro:
        return f"<h1>Resultados de búsqueda: {parametro}</h1>"
        
    return "Página funcionando con normalidad."

if __name__ == '__main__':
    # Lo corremos en el puerto 5001
    app_victima.run(port=5001, debug=True)