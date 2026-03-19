import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qsl, urlencode, urlsplit, urlunsplit
import re
import os
import base64
import time
from difflib import SequenceMatcher


class ScanConnectivityError(RuntimeError):
    """Error controlado cuando no hay conectividad suficiente para escanear."""
    pass


def calcular_severidad_virustotal(malicious, suspicious, harmless=0, undetected=0):
    """Calcula severidad para reputacion de URL segun cantidad de motores detectando riesgo."""
    try:
        malicious = max(0, int(malicious or 0))
        suspicious = max(0, int(suspicious or 0))
        harmless = max(0, int(harmless or 0))
        undetected = max(0, int(undetected or 0))
    except Exception:
        return "Baja"

    detecciones = malicious + suspicious
    total_motores = malicious + suspicious + harmless + undetected
    tasa_deteccion = (detecciones / total_motores) if total_motores > 0 else 0

    # Umbrales conservadores: 1 motor no debe elevar automaticamente a "Alta".
    if malicious >= 5 or detecciones >= 8 or tasa_deteccion >= 0.20:
        return "Alta"
    if malicious >= 2 or detecciones >= 3 or tasa_deteccion >= 0.05:
        return "Media"
    return "Baja"


def _analizar_url_virustotal(url):
    """Consulta reputacion de URL en VirusTotal si hay API key configurada."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return None

    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url_info = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        info_res = requests.get(vt_url_info, headers=headers, timeout=20)

        # Si no existe analisis previo, se envia URL para analisis y se intenta leerlo.
        if info_res.status_code == 404:
            submit_res = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=20,
            )
            if submit_res.status_code not in (200, 202):
                return {
                    "tipo": "VirusTotal",
                    "severidad": "Baja",
                    "descripcion": f"No se pudo enviar URL a VirusTotal (status {submit_res.status_code})",
                    "parametro": "URL objetivo",
                    "payload": "N/A",
                }

            # Espera breve para permitir que VT procese el analisis inicial.
            time.sleep(2)
            info_res = requests.get(vt_url_info, headers=headers, timeout=20)

        if info_res.status_code != 200:
            return {
                "tipo": "VirusTotal",
                "severidad": "Baja",
                "descripcion": f"No se pudo obtener reporte de VirusTotal (status {info_res.status_code})",
                "parametro": "URL objetivo",
                "payload": "N/A",
            }

        data = info_res.json()
        stats = data.get("data", {}).get(
            "attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

        severidad = calcular_severidad_virustotal(
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
        )

        return {
            "tipo": "VirusTotal URL Reputation",
            "severidad": severidad,
            "descripcion": (
                f"VT detecciones -> malicious: {malicious}, suspicious: {suspicious}, "
                f"harmless: {harmless}, undetected: {undetected}"
            ),
            "parametro": "URL objetivo",
            "payload": "N/A",
        }
    except Exception as e:
        return {
            "tipo": "VirusTotal",
            "severidad": "Baja",
            "descripcion": f"Error consultando VirusTotal: {e}",
            "parametro": "URL objetivo",
            "payload": "N/A",
        }


def _crear_sesion_http():
    """Crea una sesion HTTP con reintentos para mitigar fallos temporales de red."""
    reintentos = Retry(
        total=1,
        connect=1,
        read=1,
        backoff_factor=0.3,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
    )
    adapter = HTTPAdapter(max_retries=reintentos)
    sesion = requests.Session()
    sesion.mount("http://", adapter)
    sesion.mount("https://", adapter)
    return sesion


def _inyectar_payload_en_query(url, payload):
    """Genera URLs inyectando payload en cada parametro query individualmente."""
    try:
        parsed = urlsplit(url)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_items:
            return [url + payload]

        urls = []
        for idx, (k, v) in enumerate(query_items):
            mutados = list(query_items)
            # Variante 1: append al valor existente
            mutados[idx] = (k, f"{v}{payload}")
            nueva_query = urlencode(mutados, doseq=True)
            urls.append(
                urlunsplit((parsed.scheme, parsed.netloc,
                           parsed.path, nueva_query, parsed.fragment))
            )

            # Variante 2: reemplazo total del valor por payload
            mutados = list(query_items)
            mutados[idx] = (k, payload)
            nueva_query = urlencode(mutados, doseq=True)
            urls.append(
                urlunsplit((parsed.scheme, parsed.netloc,
                           parsed.path, nueva_query, parsed.fragment))
            )

        # Evitar duplicados manteniendo orden.
        return list(dict.fromkeys(urls))
    except Exception:
        return [url + payload]


def _normalizar_texto_respuesta(texto):
    """Reduce ruido dinamico para comparar respuestas HTTP de forma mas estable."""
    limpio = (texto or '').lower()
    limpio = re.sub(r'\d{2,}', '0', limpio)
    limpio = re.sub(r'\s+', ' ', limpio).strip()
    return limpio[:20000]


def _similitud_respuestas(a, b):
    return SequenceMatcher(
        None,
        _normalizar_texto_respuesta(a),
        _normalizar_texto_respuesta(b),
    ).ratio()


def _medir_respuesta(sesion_http, url_objetivo, headers, timeout_segundos):
    """Ejecuta GET y devuelve metrica minima de respuesta para analisis comparativo."""
    res = sesion_http.get(url_objetivo, headers=headers,
                          timeout=timeout_segundos)
    return {
        "status": int(res.status_code),
        "url_final": str(getattr(res, "url", url_objetivo) or url_objetivo),
        "texto": res.text or "",
        "segundos": float(getattr(res, "elapsed", 0).total_seconds() if getattr(res, "elapsed", None) else 0.0),
    }


def _contar_indicadores(texto):
    """Cuenta senales de "resultados" para comparar respuestas true/false."""
    t = (texto or "").lower()
    patrones = [
        r"<tr", r"<td", r"<li", r"product", r"resultado", r"results?",
        r"account", r"balance", r"item", r"detalle",
    ]
    return sum(len(re.findall(p, t)) for p in patrones)


def _es_posible_sqli_booleana(base, true_resp, false_resp):
    """Heuristica para SQLi ciega booleana basada en diferencias consistentes."""
    if true_resp["status"] != false_resp["status"]:
        return True

    if true_resp["url_final"] != false_resp["url_final"]:
        return True

    sim_true_false = _similitud_respuestas(
        true_resp["texto"], false_resp["texto"])
    sim_true_base = _similitud_respuestas(true_resp["texto"], base["texto"])
    sim_false_base = _similitud_respuestas(false_resp["texto"], base["texto"])

    ind_true = _contar_indicadores(true_resp["texto"])
    ind_false = _contar_indicadores(false_resp["texto"])

    # Caso clasico: true se parece al baseline y false diverge fuerte.
    if sim_true_base >= 0.90 and sim_false_base <= 0.80:
        return True

    # Diferencia fuerte entre true/false.
    if sim_true_false <= 0.88:
        return True

    # Cambios notorios en cantidad de items/resultados.
    if abs(ind_true - ind_false) >= 6:
        return True

    return False


def iniciar_escaneo_completo(url):
    resultados = []
    sesion_http = _crear_sesion_http()
    timeout_segundos = int(os.getenv('SCAN_HTTP_TIMEOUT', '10'))
    sqli_max_segundos = int(os.getenv('SCAN_SQLI_MAX_SECONDS', '45'))
    max_errores_red = int(os.getenv('SCAN_MAX_NETWORK_ERRORS', '4'))
    usar_time_based = os.getenv('SCAN_SQLI_TIME_BASED', 'false').strip().lower() in (
        '1', 'true', 'yes', 'si', 'on'
    )
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}

    print(f"\n[+] Iniciando escaneo avanzado (Fuzzing) en: {url}")

    errores_red = 0

    def registrar_error_red(detalle):
        nonlocal errores_red
        errores_red += 1
        print(f"[-] Error de red ({errores_red}/{max_errores_red}): {detalle}")
        if errores_red >= max_errores_red:
            raise ScanConnectivityError(
                'No se pudo completar el escaneo por problemas de conexión con la página objetivo. '
                'Verifica que la URL esté disponible e intenta nuevamente.'
            )

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
                   "unclosed quotation", "odbc", "sqlite", "microsoft", "ole db",
                   "sqlstate", "query failed", "mysql_fetch", "native client"]

    payloads_booleanos = [
        ("' OR '1'='1'-- ", "' OR '1'='2'-- "),
        ('" OR "1"="1"-- ', '" OR "1"="2"-- '),
        ("') OR ('1'='1'-- ", "') OR ('1'='2'-- "),
        ("1 OR 1=1", "1 AND 1=2"),
        ("1') OR ('1'='1", "1') AND ('1'='2"),
    ]

    payloads_time_based = [
        ("' OR SLEEP(5)-- ", "' OR SLEEP(0)-- "),
        ("'; WAITFOR DELAY '0:0:5'--", "'; WAITFOR DELAY '0:0:0'--"),
        ("' OR (SELECT pg_sleep(5))--", "' OR (SELECT pg_sleep(0))--"),
    ]

    # --- PRUEBA 1: SQL Injection Avanzado (GET) ---
    print("[*] Ejecutando Fuzzing de SQLi por URL...")
    inicio_sqli = time.time()

    def sqli_timeout_superado():
        return (time.time() - inicio_sqli) >= sqli_max_segundos

    baseline_data = {"status": 0, "url_final": url,
                     "texto": "", "segundos": 0.0}
    try:
        baseline_data = _medir_respuesta(
            sesion_http, url, headers, timeout_segundos)
    except requests.exceptions.RequestException as e:
        print(f"[-] Error de conectividad inicial: {e}")
        raise ScanConnectivityError(
            'No se pudo conectar con la página objetivo. '
            'Verifica que la URL esté disponible e intenta nuevamente.'
        )

    for payload in payloads_sqli:
        if sqli_timeout_superado():
            print(
                f"[-] SQLi: tiempo maximo alcanzado ({sqli_max_segundos}s). Se continua con las siguientes pruebas.")
            break

        print(f"[*] SQLi payload en prueba: {payload}")
        urls_objetivo = _inyectar_payload_en_query(url, payload)
        for url_sqli in urls_objetivo:
            if sqli_timeout_superado():
                break
            try:
                res = sesion_http.get(
                    url_sqli, headers=headers, timeout=timeout_segundos)
                contenido = res.text.lower()

                if any(error in contenido for error in errores_sql):
                    print(f">>> 🔴 ¡SQLi detectado con el payload: {payload}")
                    resultados.append({
                        "tipo": f"SQL Injection",
                        "severidad": "Alta",
                        "descripcion": f"Error SQL detectado con payload: {payload}",
                        "parametro": "URL (consulta/ruta)",
                        "payload": payload,
                    })
                    break
            except requests.exceptions.Timeout:
                registrar_error_red(
                    f"SQLi timeout con {url_sqli} (timeout={timeout_segundos}s)")
                continue
            except requests.exceptions.RequestException as e:
                registrar_error_red(f"SQLi fallo de conexión con {url_sqli}: {e}")
                continue
            except Exception as e:
                print(f"[-] Error SQLi: {e}")
                continue

        if any(r.get("tipo") == "SQL Injection" for r in resultados):
            break

    # Verificacion booleana simple para SQLi ciega en parametros query.
    if not any(r.get("tipo") == "SQL Injection" for r in resultados):
        for payload_true, payload_false in payloads_booleanos:
            if sqli_timeout_superado():
                print(
                    f"[-] SQLi booleana: tiempo maximo alcanzado ({sqli_max_segundos}s).")
                break

            print(
                f"[*] SQLi booleana en prueba: true='{payload_true}' / false='{payload_false}'")
            urls_true = _inyectar_payload_en_query(url, payload_true)
            urls_false = _inyectar_payload_en_query(url, payload_false)
            total_pairs = min(len(urls_true), len(urls_false))

            for i in range(total_pairs):
                if sqli_timeout_superado():
                    break
                try:
                    true_data = _medir_respuesta(
                        sesion_http, urls_true[i], headers, timeout_segundos)
                    false_data = _medir_respuesta(
                        sesion_http, urls_false[i], headers, timeout_segundos)

                    if _es_posible_sqli_booleana(baseline_data, true_data, false_data):
                        print(
                            ">>> 🟠 Posible SQLi ciega detectada por diferencia true/false")
                        resultados.append({
                            "tipo": "SQL Injection (posible ciega)",
                            "severidad": "Media",
                            "descripcion": "Respuesta diferente entre payload booleano verdadero y falso.",
                            "parametro": "URL (consulta/ruta)",
                            "payload": payload_true,
                        })
                        break
                except requests.exceptions.Timeout:
                    registrar_error_red(
                        f"SQLi booleana timeout (timeout={timeout_segundos}s)")
                    continue
                except requests.exceptions.RequestException as e:
                    registrar_error_red(
                        f"SQLi booleana fallo de conexión: {e}")
                    continue
                except Exception:
                    continue

            if any(r.get("tipo") == "SQL Injection (posible ciega)" for r in resultados):
                break

    # Verificacion time-based para escenarios donde no hay errores ni cambios visibles.
    if usar_time_based and not any("SQL Injection" in str(r.get("tipo", "")) for r in resultados):
        for payload_lento, payload_control in payloads_time_based:
            if sqli_timeout_superado():
                print(
                    f"[-] SQLi time-based: tiempo maximo alcanzado ({sqli_max_segundos}s).")
                break

            print(
                f"[*] SQLi time-based en prueba: slow='{payload_lento}' / control='{payload_control}'")
            urls_lentas = _inyectar_payload_en_query(url, payload_lento)
            urls_control = _inyectar_payload_en_query(url, payload_control)
            total_pairs = min(len(urls_lentas), len(urls_control))

            for i in range(total_pairs):
                if sqli_timeout_superado():
                    break
                try:
                    lenta = _medir_respuesta(
                        sesion_http, urls_lentas[i], headers, timeout_segundos + 8)
                    control = _medir_respuesta(
                        sesion_http, urls_control[i], headers, timeout_segundos + 8)

                    delta = lenta["segundos"] - control["segundos"]
                    if delta >= 3.5:
                        print(
                            ">>> 🟠 Posible SQLi ciega detectada por retardo (time-based)")
                        resultados.append({
                            "tipo": "SQL Injection (posible ciega)",
                            "severidad": "Media",
                            "descripcion": f"Retardo anomalo detectado entre payload SQLi y control (delta={delta:.2f}s).",
                            "parametro": "URL (consulta/ruta)",
                            "payload": payload_lento,
                        })
                        break
                except requests.exceptions.Timeout:
                    registrar_error_red(
                        f"SQLi time-based timeout (timeout={timeout_segundos + 8}s)")
                    continue
                except requests.exceptions.RequestException as e:
                    registrar_error_red(
                        f"SQLi time-based fallo de conexión: {e}")
                    continue
                except Exception:
                    continue

            if any(r.get("tipo") == "SQL Injection (posible ciega)" for r in resultados):
                break
    elif not usar_time_based:
        print("[*] SQLi time-based desactivado (SCAN_SQLI_TIME_BASED=false).")

    # --- PRUEBA 2: XSS Avanzado (GET) ---
    print("[*] Ejecutando Fuzzing de XSS por URL...")

    for payload in payloads_xss:
        url_xss = url + payload
        try:
            res = sesion_http.get(
                url_xss, headers=headers, timeout=timeout_segundos)
            contenido = res.text
            contenido_lower = contenido.lower()

            # MÉTODO 1: Buscar payload exacto (funciona en victima.py)
            if payload in contenido:
                print(f">>> 🟡 ¡XSS detectado con payload exacto!")
                resultados.append({
                    "tipo": "XSS Reflejado",
                    "severidad": "Media",
                    "descripcion": f"Payload reflejado exactamente",
                    "parametro": "URL (consulta/ruta)",
                    "payload": payload,
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
                    "descripcion": f"Patrón XSS detectado",
                    "parametro": "URL (consulta/ruta)",
                    "payload": payload,
                })
                break

            # MÉTODO 3: Buscar funciones JavaScript comunes
            funciones_js = ["alert(", "prompt(", "confirm("]
            if any(func in contenido_lower for func in funciones_js):
                print(f">>> 🟡 ¡Posible XSS detectado por función JS!")
                resultados.append({
                    "tipo": "XSS Reflejado",
                    "severidad": "Media",
                    "descripcion": f"Función JavaScript detectada",
                    "parametro": "URL (consulta/ruta)",
                    "payload": payload,
                })
                break

        except requests.exceptions.Timeout:
            registrar_error_red(
                f"XSS timeout con {url_xss} (timeout={timeout_segundos}s)")
            continue
        except requests.exceptions.RequestException as e:
            registrar_error_red(f"XSS fallo de conexión con {url_xss}: {e}")
            continue
        except Exception as e:
            print(f"[-] Error XSS: {e}")
            continue

    # --- PRUEBA 3: ESCANEO DE FORMULARIOS AVANZADO (POST) ---
    print("[*] Buscando y atacando formularios con Fuzzing...")
    try:
        res = sesion_http.get(url, headers=headers, timeout=timeout_segundos)
        soup = BeautifulSoup(res.text, "html.parser")
        formularios = soup.find_all("form")

        if formularios:
            for form in formularios:
                action = form.get("action")
                target_url = urljoin(url, action) if action else url
                inputs = form.find_all("input")
                nombres_inputs = [inp.get("name")
                                  for inp in inputs if inp.get("name")]
                parametro_form = ", ".join(
                    nombres_inputs) if nombres_inputs else "Campos de formulario"

                vulnerabilidad_encontrada = False

                # Probamos SQLi en formularios
                for payload in payloads_sqli:
                    datos_falsos = {}
                    for inp in inputs:
                        nombre = inp.get("name")
                        if nombre:
                            datos_falsos[nombre] = payload

                    try:
                        res_post = sesion_http.post(
                            target_url, data=datos_falsos, headers=headers, timeout=timeout_segundos)

                        if any(error in res_post.text.lower() for error in errores_sql):
                            print(
                                f">>> 🔴 ¡SQLi en Formulario detectado con: {payload}")
                            resultados.append({
                                "tipo": "SQL Injection en Formulario",
                                "severidad": "Alta",
                                "descripcion": f"SQLi en POST con payload: {payload}",
                                "parametro": parametro_form,
                                "payload": payload,
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
                        res_post = sesion_http.post(
                            target_url, data=datos_falsos, headers=headers, timeout=timeout_segundos)

                        if payload in res_post.text:
                            print(f">>> 🟡 ¡XSS en Formulario detectado!")
                            resultados.append({
                                "tipo": "XSS en Formulario",
                                "severidad": "Media",
                                "descripcion": f"XSS en POST detectado",
                                "parametro": parametro_form,
                                "payload": payload,
                            })
                            vulnerabilidad_encontrada = True
                            break
                    except:
                        pass

                if vulnerabilidad_encontrada:
                    break
        else:
            print("[*] No hay formularios en esta página.")
    except ScanConnectivityError:
        raise
    except requests.exceptions.RequestException as e:
        print(f"[-] Error de conectividad en formularios: {e}")
        raise ScanConnectivityError(
            'No se pudo continuar el análisis por problemas de conexión con la página objetivo. '
            'Intenta nuevamente en unos segundos.'
        )
    except Exception as e:
        print(f"[-] Error al analizar formularios: {e}")
    finally:
        sesion_http.close()

    # --- RESULTADO FINAL ---
    # --- PRUEBA 4: REPUTACION CON VIRUSTOTAL (OPCIONAL) ---
    print("[*] Consultando VirusTotal (si API key esta configurada)...")
    resultado_vt = _analizar_url_virustotal(url)
    if resultado_vt:
        resultados.append(resultado_vt)

    if not resultados:
        print("[!] Fin del escaneo: Ninguna detectada.")
        resultados.append({"tipo": "Ninguna detectada", "severidad": "Baja"})

    return resultados
