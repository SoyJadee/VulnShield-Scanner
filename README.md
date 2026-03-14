# 🛡️ VulnShield Scanner v1.0

VulnShield es una herramienta de **Análisis Dinámico de Seguridad (DAST)** desarrollada como proyecto de Ingeniería de Sistemas para la Universidad Santa María (USM). 

El sistema permite automatizar la detección de vulnerabilidades críticas en aplicaciones web mediante técnicas de **Fuzzing dinámico**, analizando tanto parámetros de URL (GET) como formularios de entrada de datos (POST).

## ✨ Características Principales

* **Motor de Fuzzing Avanzado:** No solo realiza pruebas estáticas, sino que bombardea el objetivo con múltiples diccionarios de ataques.
* **Detección de SQL Injection (SQLi):** Identifica vulnerabilidades basadas en errores en motores MySQL, PostgreSQL, Oracle y Java.
* **Detección de Cross-Site Scripting (XSS):** Valida si la aplicación permite la inyección de scripts maliciosos en el DOM.
* **Análisis de Formularios:** Escaneo automático de etiquetas `<form>` y simulación de peticiones POST para auditar sistemas de autenticación.
* **Auditoría en Tiempo Real:** Los resultados se almacenan en una base de datos relacional para su posterior revisión.
* **Dashboard Moderno:** Interfaz intuitiva con sistema de alertas por colores según la severidad (Alta/Media/Baja).

## 🛠️ Stack Tecnológico

* **Lenguaje:** Python 3.x
* **Framework Web:** Flask (Backend)
* **Base de Datos:** PostgreSQL
* **Librerías Clave:** `requests`, `BeautifulSoup4`, `psycopg2`.
* **Frontend:** HTML5 + Tailwind CSS.

---

## 🚀 Guía de Instalación para el Equipo

Para que el proyecto funcione en tu computadora local, sigue estos pasos:

### 1. Configuración de la Base de Datos
Debes tener instalado **PostgreSQL**. Abre tu terminal de base de datos o pgAdmin y crea la base de datos:
1.  Crea una base de datos llamada: `vulnshield_db`
2.  Asegúrate de que el usuario `jade` tenga la contraseña: `123456`
3.  El sistema creará las tablas automáticamente al iniciar.

### 2. Clonación y Entorno Virtual
Abre una terminal en la carpeta del proyecto y ejecuta:

**En Windows:**
```bash
python -m venv venv
venv\Scripts\activate

Con el entorno virtual activado (venv), instala los requerimientos:
pip install -r requirements.txt

Inicia el servidor de Flask:
python app.py
Accede en tu navegador a: http://127.0.0.1:5000

Gemini ha dicho
¡Claro que sí, Jade! Aquí tienes el archivo README.md completo, redactado con un tono súper profesional para que cuando tus compañeros (o el profesor) lo vean, piensen que es un software de una empresa de seguridad real.

He incluido la explicación de las vulnerabilidades, los pasos de instalación y la configuración de la base de datos para que no se pierdan.

Copia y pega todo el bloque de abajo en un archivo nuevo llamado README.md en tu carpeta principal:

Markdown
# 🛡️ VulnShield Scanner v1.0

VulnShield es una herramienta de **Análisis Dinámico de Seguridad (DAST)** desarrollada como proyecto de Ingeniería de Sistemas para la Universidad Santa María (USM). 

El sistema permite automatizar la detección de vulnerabilidades críticas en aplicaciones web mediante técnicas de **Fuzzing dinámico**, analizando tanto parámetros de URL (GET) como formularios de entrada de datos (POST).

## ✨ Características Principales

* **Motor de Fuzzing Avanzado:** No solo realiza pruebas estáticas, sino que bombardea el objetivo con múltiples diccionarios de ataques.
* **Detección de SQL Injection (SQLi):** Identifica vulnerabilidades basadas en errores en motores MySQL, PostgreSQL, Oracle y Java.
* **Detección de Cross-Site Scripting (XSS):** Valida si la aplicación permite la inyección de scripts maliciosos en el DOM.
* **Análisis de Formularios:** Escaneo automático de etiquetas `<form>` y simulación de peticiones POST para auditar sistemas de autenticación.
* **Auditoría en Tiempo Real:** Los resultados se almacenan en una base de datos relacional para su posterior revisión.
* **Dashboard Moderno:** Interfaz intuitiva con sistema de alertas por colores según la severidad (Alta/Media/Baja).

## 🛠️ Stack Tecnológico

* **Lenguaje:** Python 3.x
* **Framework Web:** Flask (Backend)
* **Base de Datos:** PostgreSQL
* **Librerías Clave:** `requests`, `BeautifulSoup4`, `psycopg2`.
* **Frontend:** HTML5 + Tailwind CSS.

---

## 🚀 Guía de Instalación para el Equipo

Para que el proyecto funcione en tu computadora local, sigue estos pasos:

### 1. Configuración de la Base de Datos
Debes tener instalado **PostgreSQL**. Abre tu terminal de base de datos o pgAdmin y crea la base de datos:
1.  Crea una base de datos llamada: `vulnshield_db`
2.  Asegúrate de que el usuario `postgres` tenga la contraseña: `admin123`
3.  El sistema creará las tablas automáticamente al iniciar.

### 2. Clonación y Entorno Virtual
Abre una terminal en la carpeta del proyecto y ejecuta:

**En Windows:**
```bash
python -m venv venv
venv\Scripts\activate
En Linux/Ubuntu (Jade's choice):

Bash
python3 -m venv venv
source venv/bin/activate
3. Instalación de Dependencias
Con el entorno virtual activado (venv), instala los requerimientos:

Bash
pip install -r requirements.txt
4. Lanzamiento del Sistema
Inicia el servidor de Flask:

Bash
python app.py
Accede en tu navegador a: http://127.0.0.1:5000

🔬 ¿Cómo realizar pruebas seguras?
Para evitar problemas legales o bloqueos de red, el proyecto incluye un Servidor Víctima para pruebas locales:

Abre otra terminal y activa el entorno virtual.

Ejecuta: python victima.py

En el escáner web, ingresa la URL local: http://127.0.0.1:5001/buscar?q=1

Prueba externa sugerida: http://demo.testfire.net/login.jsp (Laboratorio oficial de IBM).