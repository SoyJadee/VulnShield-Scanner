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

-------------------------------------

## 🚀 Guía de Instalación para el Equipo

Para que el proyecto funcione en tu computadora local, sigue estos pasos:

### 1. Configuración de la Base de Datos
Debes tener instalado **PostgreSQL**. Abre tu terminal de base de datos o pgAdmin y crea la base de datos:
1.  Crea una base de datos llamada: `vulnshield_db`
2.  Asegúrate de que el usuario `jade` tenga la contraseña: `123456`
3.  El sistema creará las tablas automáticamente al iniciar la base de datos.

### 2. Clonación y Entorno Virtual
Abre una terminal en la carpeta del proyecto o desde VisualStudioCode y ejecuta:

**En Windows:**
```bash
python -m venv venv
venv\Scripts\activate

Con el entorno virtual activado (venv), instala los requerimientos:
pip install -r requirements.txt

# INICIAR APLICACION EN SU COMPUADORA LOCAL
Inicia el servidor de Flask:
python app.py
Accede en tu navegador a: http://127.0.0.1:5000

# INICIAR UN ENTORNO VIRTUAL DE VICTIMA PARA PRUEBAS SEGURAS
Para ejecutar un entorno virtual de victima de ataque
Abre otra terminal y activa el entorno virtual.
Ejecuta: python victima.py

En el escáner web, ingresa la URL local: http://127.0.0.1:5001/buscar?q=1

----------------------------

Listado de url para poder escanear de forma segura:

# del entorno virtual de victima.py (solo http)
- http://127.0.0.1:5001/buscar?q=1
- http://127.0.0.1:5001/login
- http://127.0.0.1:5001/comentarios

# url de laboratorios publicos y seguros (http)
- http://demo.testfire.net/login.jsp
- http://testphp.vulnweb.com/
- http://zero.webappsecurity.com/login.html
- http://www.webscantest.com/
- http://xss-game.appspot.com/level1

# url de laboratorios publicos y seguros (https)
- https://demo.testfire.net/login.jsp
- https://testphp.vulnweb.com/
- https://zero.webappsecurity.com/login.html
- https://www.webscantest.com/
- https://xss-game.appspot.com/level1
- https://www.hackthissite.org/
- https://bodgeit.appspot.com/
- https://juice-shop.herokuapp.com/

# IMPORTANTE: para que la funcion de envio de correo funcione se ve instalar lo siguiente
pip install python-dotenv

# ADMINISTRADORES
Si en su computadora local no hay ningun administrador, el sistema creara un administrador automaticamente para ingresar al apartado
de administradores
Las credenciales del administrador son:
- usuario: admin
- correo: admin@vulnshield.com
- clave: admin123

# PROBLEMA CON EL ADMINISTRADOR
si en su computadora local ya se encuentra un administrador, pero le aparece error con la base de datos siga los pasos:
- Ingresar en postgreSQL con su contraseña maestra
- Dirigirse a la base de datos 'vulnshield_db'
- Busque la tabla de usuarios, de click derecho y luego en editar y ver
- Seleccione el usuario admin y eliminelo
- Inicie de nuevo app.py

Con estos pasos se creara un adminstrador desde cero y podra ingresar

# ENVIO DE CORREO
crear un archivo .env y colocar esto
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vulnshield_db
DB_USER=jade
DB_PASSWORD=123456
VIRUSTOTAL_API_KEY=26f506a1c848e3b47d90fdb7e5c2eaf3b36e84c146485eb1cd9ecaf6b73e3f60
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=vulnshieldScanner@gmail.com
SMTP_PASSWORD=grpjgcvuhyyjaqvd
SMTP_FROM=vulnshieldScanner@gmail.com
SMTP_USE_TLS=true