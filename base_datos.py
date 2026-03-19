import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime


def _cargar_env_local():
    """Carga .env local si existe (sin requerir python-dotenv)."""
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception as e:
        print(f"Aviso: no se pudo cargar .env: {e}")


def _obtener_db_config():
    return {
        "dbname": os.getenv("DB_NAME", "vulnshield_db"),
        "user": os.getenv("DB_USER", "jade"),
        "password": os.getenv("DB_PASSWORD", "123456"),
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
    }


_cargar_env_local()


def conectar():
    """Establece conexion con la base de datos."""
    db_config = _obtener_db_config()
    try:
        return psycopg2.connect(**db_config)
    except Exception as e:
        print(
            "Error de base de datos "
            f"(Host: {db_config.get('host')}, Puerto: {db_config.get('port')}, Usuario: {db_config.get('user')}): {e}"
        )
        print("Sugerencia: verifica DB_HOST/DB_PORT/DB_USER/DB_PASSWORD en .env")
        return None


def _normalizar_tipo(tipo):
    if not tipo:
        return "Desconocida"
    if "SQL" in tipo:
        return "SQL Injection"
    if "XSS" in tipo:
        return "XSS"
    return tipo.split(" - ")[0].strip()


def _normalizar_severidad(nombre):
    valor = str(nombre or '').strip().lower()
    if valor in ('critico', 'crítico'):
        return 'Critico'
    if valor in ('alto', 'alta'):
        return 'Alto'
    if valor == 'medio':
        return 'Medio'
    if valor in ('bajo', 'baja'):
        return 'Bajo'
    return 'Medio'


def _asegurar_id_admin(cursor):
    """Asegura que existe el usuario admin y devuelve su ID."""
    # Verificar si ya existe admin por username o correo
    cursor.execute(
        'SELECT "idUsuario" FROM "Usuario" WHERE username = %s OR correo = %s',
        ('admin', 'admin@vulnshield.com')
    )
    row = cursor.fetchone()
    if row:
        return row[0]

    # Si no existe, crear admin con contraseña 'admin123'
    from werkzeug.security import generate_password_hash
    admin_hash = generate_password_hash('admin123')

    cursor.execute(
        '''
        INSERT INTO "Usuario" (username, correo, password_hash, "inRol")
        VALUES (%s, %s, %s, %s)
        RETURNING "idUsuario"
        ''',
        (
            "admin",
            "admin@vulnshield.com",
            admin_hash,
            True,
        ),
    )
    admin_id = cursor.fetchone()[0]
    print(f"✅ Usuario admin creado con ID: {admin_id}")
    return admin_id


def inicializar_db():
    """Crea solo las tablas solicitadas por el usuario."""
    conexion = conectar()
    if not conexion:
        return

    cursor = conexion.cursor()
    try:
        print("Verificando y creando esquema solicitado...")

        # Elimina tablas antiguas no deseadas.
        cursor.execute('DROP TABLE IF EXISTS hallazgos CASCADE')
        cursor.execute('DROP TABLE IF EXISTS analisis CASCADE')
        cursor.execute('DROP TABLE IF EXISTS protocolos CASCADE')
        cursor.execute('DROP TABLE IF EXISTS tipos_vulnerabilidad CASCADE')
        cursor.execute('DROP TABLE IF EXISTS administradores CASCADE')
        cursor.execute('DROP TABLE IF EXISTS usuarios CASCADE')

        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS "Usuario" (
                "idUsuario" SERIAL PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                correo VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                "inRol" BOOLEAN NOT NULL DEFAULT FALSE
            )
            '''
        )

        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS "niveles_severidad" (
                "id_severidad" SERIAL PRIMARY KEY,
                "Nombre" VARCHAR(20) UNIQUE NOT NULL,
                color_hex VARCHAR(7) NOT NULL
            )
            '''
        )

        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS "Escaneo" (
                "idEscaneo" SERIAL PRIMARY KEY,
                "idUsuario" INTEGER NOT NULL,
                url_objetivo TEXT NOT NULL,
                fecha TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_escaneo_usuario
                    FOREIGN KEY ("idUsuario") REFERENCES "Usuario"("idUsuario")
                    ON DELETE CASCADE
            )
            '''
        )

        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS "catalogo_Vulnerabilidad" (
                "idvulnerabilidad" SERIAL PRIMARY KEY,
                "idseveridad" INTEGER NOT NULL,
                "Nombre" VARCHAR(80) UNIQUE NOT NULL,
                "Descripcion" TEXT,
                "Recomendacion" TEXT,
                CONSTRAINT fk_catalogo_severidad
                    FOREIGN KEY ("idseveridad") REFERENCES "niveles_severidad"("id_severidad")
            )
            '''
        )

        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS "hallazgo" (
                "idHallazgo" SERIAL PRIMARY KEY,
                "idEscaneo" INTEGER NOT NULL,
                "idVulnerabilidad" INTEGER NOT NULL,
                "idseveridad" INTEGER,
                parametro TEXT,
                payload TEXT,
                CONSTRAINT fk_hallazgo_escaneo
                    FOREIGN KEY ("idEscaneo") REFERENCES "Escaneo"("idEscaneo")
                    ON DELETE CASCADE,
                CONSTRAINT fk_hallazgo_vulnerabilidad
                    FOREIGN KEY ("idVulnerabilidad") REFERENCES "catalogo_Vulnerabilidad"("idvulnerabilidad"),
                CONSTRAINT fk_hallazgo_severidad
                    FOREIGN KEY ("idseveridad") REFERENCES "niveles_severidad"("id_severidad")
            )
            '''
        )

        # Migracion para instalaciones previas: severidad por hallazgo.
        cursor.execute(
            'ALTER TABLE "hallazgo" ADD COLUMN IF NOT EXISTS "idseveridad" INTEGER'
        )

        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_escaneo_usuario ON "Escaneo"("idUsuario")')
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_escaneo_fecha ON "Escaneo"(fecha)')
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_hallazgo_escaneo ON "hallazgo"("idEscaneo")')

        severidades = [
            ("Critico", "#FF4444"),
            ("Alto", "#FF8800"),
            ("Medio", "#FFCC00"),
            ("Bajo", "#00AEEF"),
        ]
        for nombre, color in severidades:
            cursor.execute(
                '''
                INSERT INTO "niveles_severidad" ("Nombre", color_hex)
                VALUES (%s, %s)
                ON CONFLICT ("Nombre") DO NOTHING
                ''',
                (nombre, color),
            )

        admin_id = _asegurar_id_admin(cursor)

        catalogo_inicial = [
            (
                "SQL Injection",
                "Critico",
                "Inyeccion SQL detectada",
                "Usar consultas parametrizadas y validar entradas",
            ),
            (
                "XSS",
                "Alto",
                "Cross-Site Scripting detectado",
                "Escapar salida HTML y sanitizar datos de entrada",
            ),
        ]
        for nombre, nivel_nombre, descripcion, recomendacion in catalogo_inicial:
            cursor.execute(
                'SELECT "id_severidad" FROM "niveles_severidad" WHERE "Nombre" = %s',
                (nivel_nombre,),
            )
            sev_id = cursor.fetchone()[0]
            cursor.execute(
                '''
                INSERT INTO "catalogo_Vulnerabilidad"
                ("idseveridad", "Nombre", "Descripcion", "Recomendacion")
                VALUES (%s, %s, %s, %s)
                ON CONFLICT ("Nombre") DO NOTHING
                ''',
                (sev_id, nombre, descripcion, recomendacion),
            )

        conexion.commit()
        print(f"Base de datos inicializada. Usuario admin id: {admin_id}")
    except Exception as e:
        conexion.rollback()
        print(f"Error inicializando esquema: {e}")
    finally:
        cursor.close()
        conexion.close()


def guardar_analisis_completo(url, protocolo, administrador_id, hallazgos_list, tiempo_ejecucion=0):
    """Guarda un escaneo y sus hallazgos en el nuevo esquema."""
    conexion = conectar()
    if not conexion:
        return None

    cursor = conexion.cursor()

    try:
        cursor.execute(
            'SELECT "idUsuario" FROM "Usuario" WHERE "idUsuario" = %s', (administrador_id,))
        existe_usuario = cursor.fetchone()
        if not existe_usuario:
            administrador_id = _asegurar_id_admin(cursor)

        cursor.execute(
            '''
            INSERT INTO "Escaneo" ("idUsuario", url_objetivo)
            VALUES (%s, %s)
            RETURNING "idEscaneo"
            ''',
            (administrador_id, url),
        )
        escaneo_id = cursor.fetchone()[0]

        for hallazgo in hallazgos_list:
            tipo = _normalizar_tipo(hallazgo.get('tipo', ''))
            severidad_nombre = _normalizar_severidad(hallazgo.get('severidad'))
            cursor.execute(
                'SELECT "id_severidad" FROM "niveles_severidad" WHERE "Nombre" = %s',
                (severidad_nombre,),
            )
            sev = cursor.fetchone()
            sev_id = sev[0] if sev else 3

            cursor.execute(
                'SELECT "idvulnerabilidad" FROM "catalogo_Vulnerabilidad" WHERE "Nombre" = %s',
                (tipo,),
            )
            row = cursor.fetchone()

            if not row:
                cursor.execute(
                    '''
                    INSERT INTO "catalogo_Vulnerabilidad"
                    ("idseveridad", "Nombre", "Descripcion", "Recomendacion")
                    VALUES (%s, %s, %s, %s)
                    RETURNING "idvulnerabilidad"
                    ''',
                    (sev_id, tipo, "Detectado por escaneo",
                     "Revisar y mitigar la vulnerabilidad"),
                )
                vuln_id = cursor.fetchone()[0]
            else:
                vuln_id = row[0]

            cursor.execute(
                '''
                INSERT INTO "hallazgo" ("idEscaneo", "idVulnerabilidad", "idseveridad", parametro, payload)
                VALUES (%s, %s, %s, %s, %s)
                ''',
                (
                    escaneo_id,
                    vuln_id,
                    sev_id,
                    hallazgo.get('parametro', ''),
                    hallazgo.get('payload', ''),
                ),
            )

        conexion.commit()
        print(
            f"Escaneo #{escaneo_id} guardado con {len(hallazgos_list)} hallazgos")
        return escaneo_id
    except Exception as e:
        conexion.rollback()
        print(f"Error guardando escaneo: {e}")
        return None
    finally:
        cursor.close()
        conexion.close()


def guardar_hallazgo(url, tipo):
    """Compatibilidad con el flujo actual de escaneo."""
    hallazgos = [{
        'tipo': _normalizar_tipo(tipo),
        'parametro': '',
        'payload': ''
    }]

    return guardar_analisis_completo(
        url=url,
        protocolo='HTTP',
        administrador_id=1,
        hallazgos_list=hallazgos,
        tiempo_ejecucion=0
    )


def listar_administradores():
    """Lista todos los usuarios que son administradores (inRol = True)"""
    conexion = conectar()
    if not conexion:
        return None

    cursor = conexion.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute(
            '''
            SELECT
                "idUsuario" AS id,
                username AS usuario,
                correo AS email,
                "inRol" AS inrol
            FROM "Usuario"
            WHERE "inRol" = TRUE
            ORDER BY "idUsuario" ASC
            '''
        )
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        print(f"Error listando administradores: {e}")
        return None
    finally:
        cursor.close()
        conexion.close()


def crear_administrador(usuario, contrasena_hash, email, es_admin=False):
    """Crea un nuevo usuario en la base de datos"""
    conexion = conectar()
    if not conexion:
        return {'ok': False, 'error': 'Sin conexion a base de datos'}

    cursor = conexion.cursor()
    try:
        # Validar unicidad de correo
        cursor.execute(
            'SELECT 1 FROM "Usuario" WHERE correo = %s',
            (email,),
        )
        if cursor.fetchone():
            return {'ok': False, 'error': 'El correo ya se encuentra registrado'}

        # Validar unicidad de usuario (opcional, por si quieres que sea único)
        cursor.execute(
            'SELECT 1 FROM "Usuario" WHERE username = %s',
            (usuario,),
        )
        if cursor.fetchone():
            return {'ok': False, 'error': 'El nombre de usuario ya se encuentra registrado'}

        cursor.execute(
            '''
            INSERT INTO "Usuario" (username, correo, password_hash, "inRol")
            VALUES (%s, %s, %s, %s)
            RETURNING "idUsuario"
            ''',
            (usuario, email, contrasena_hash, es_admin),
        )
        nuevo_id = cursor.fetchone()[0]
        conexion.commit()
        return {'ok': True, 'id': nuevo_id}
    except Exception as e:
        conexion.rollback()
        return {'ok': False, 'error': str(e)}
    finally:
        cursor.close()
        conexion.close()


def eliminar_administrador(admin_id, admin_principal='admin'):
    """Elimina un administrador, evitando eliminar al principal"""
    conexion = conectar()
    if not conexion:
        return {'ok': False, 'error': 'Sin conexion a base de datos'}

    cursor = conexion.cursor()
    try:
        # Verificar que el usuario existe y es admin
        cursor.execute(
            'SELECT username FROM "Usuario" WHERE "idUsuario" = %s AND "inRol" = TRUE',
            (admin_id,),
        )
        row = cursor.fetchone()
        if not row:
            return {'ok': False, 'error': 'Administrador no encontrado'}

        # No permitir eliminar al administrador principal
        if row[0].strip().lower() == admin_principal.strip().lower():
            return {'ok': False, 'error': 'No se puede eliminar el administrador principal'}

        cursor.execute(
            'DELETE FROM "Usuario" WHERE "idUsuario" = %s', (admin_id,))
        conexion.commit()
        return {'ok': True}
    except Exception as e:
        conexion.rollback()
        return {'ok': False, 'error': str(e)}
    finally:
        cursor.close()
        conexion.close()


def obtener_administrador_por_usuario(usuario):
    """Devuelve el usuario (sin requerir que sea admin)."""
    conexion = conectar()
    if not conexion:
        return None

    cursor = conexion.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute(
            '''
            SELECT
                "idUsuario" AS id,
                username AS usuario,
                password_hash AS contrasena_hash,
                "inRol" AS activo
            FROM "Usuario"
            WHERE username = %s
            ''',
            (usuario,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    except Exception as e:
        print(f"Error obteniendo administrador: {e}")
        return None
    finally:
        cursor.close()
        conexion.close()


def obtener_administrador_por_correo(correo):
    """Devuelve el usuario por correo."""
    conexion = conectar()
    if not conexion:
        return None

    cursor = conexion.cursor(cursor_factory=RealDictCursor)
    try:
        correo_normalizado = str(correo or '').strip().lower()
        cursor.execute(
            '''
            SELECT
                "idUsuario" AS id,
                username AS usuario,
                correo AS email,
                password_hash AS contrasena_hash,
                "inRol" AS activo
            FROM "Usuario"
            WHERE LOWER(TRIM(correo)) = %s
            ''',
            (correo_normalizado,),
        )
        row = cursor.fetchone()
        print(f"Resultado BD para correo {correo_normalizado}: {row}")
        return dict(row) if row else None
    except Exception as e:
        print(f"Error obteniendo administrador por correo: {e}")
        return None
    finally:
        cursor.close()
        conexion.close()


def actualizar_ultimo_acceso(admin_id):
    """Compatibilidad: la tabla Usuario no tiene columna ultimo_acceso."""
    return True


def obtener_total_hallazgos_bd():
    """Devuelve el total acumulado de vulnerabilidades registradas en BD."""
    conexion = conectar()
    if not conexion:
        return 0

    cursor = conexion.cursor()
    try:
        cursor.execute('SELECT COUNT(*) FROM "hallazgo"')
        row = cursor.fetchone()
        return int(row[0]) if row else 0
    except Exception as e:
        print(f"Error obteniendo total de hallazgos: {e}")
        return 0
    finally:
        cursor.close()
        conexion.close()


def obtener_metricas_resumen():
    """Obtiene metricas resumidas para las tarjetas principales del dashboard."""
    conexion = conectar()
    metricas_base = {
        'total_hallazgos': 0,
        'vulnerabilidades_criticas': 0,
        'total_escaneos': 0,
        'escaneos_hoy': 0,
    }

    if not conexion:
        return metricas_base

    cursor = conexion.cursor()
    try:
        cursor.execute('SELECT COUNT(*) FROM "hallazgo"')
        row = cursor.fetchone()
        metricas_base['total_hallazgos'] = int(row[0]) if row else 0

        cursor.execute('''
            SELECT COUNT(*)
            FROM "hallazgo" h
            JOIN "catalogo_Vulnerabilidad" cv ON h."idVulnerabilidad" = cv."idvulnerabilidad"
            JOIN "niveles_severidad" ns ON ns."id_severidad" = COALESCE(h."idseveridad", cv."idseveridad")
            WHERE ns."Nombre" IN ('Critico', 'Alto')
        ''')
        row = cursor.fetchone()
        metricas_base['vulnerabilidades_criticas'] = int(row[0]) if row else 0

        cursor.execute('''
            SELECT
                COUNT(*) as total,
                COUNT(CASE WHEN fecha::date = CURRENT_DATE THEN 1 END) as hoy
            FROM "Escaneo"
        ''')
        row = cursor.fetchone()
        if row:
            metricas_base['total_escaneos'] = int(row[0])
            metricas_base['escaneos_hoy'] = int(row[1])

        return metricas_base
    except Exception as e:
        print(f"Error obteniendo metricas resumen: {e}")
        return metricas_base
    finally:
        cursor.close()
        conexion.close()


def obtener_metricas_resumen_usuario(usuario_id):
    """Obtiene metricas de escaneos para un usuario especifico."""
    metricas_base = {
        'total_escaneos': 0,
        'escaneos_hoy': 0,
    }

    conexion = conectar()
    if not conexion:
        return metricas_base

    cursor = conexion.cursor()
    try:
        cursor.execute(
            '''
            SELECT
                COUNT(*) as total,
                COUNT(CASE WHEN fecha::date = CURRENT_DATE THEN 1 END) as hoy
            FROM "Escaneo"
            WHERE "idUsuario" = %s
            ''',
            (usuario_id,),
        )
        row = cursor.fetchone()
        if row:
            metricas_base['total_escaneos'] = int(row[0] or 0)
            metricas_base['escaneos_hoy'] = int(row[1] or 0)

        return metricas_base
    except Exception as e:
        print(f"Error obteniendo metricas de usuario: {e}")
        return metricas_base
    finally:
        cursor.close()
        conexion.close()


def obtener_correo_usuario(usuario_id):
    """Devuelve el correo del usuario para envio de informes."""
    conexion = conectar()
    if not conexion:
        return None

    cursor = conexion.cursor()
    try:
        cursor.execute(
            'SELECT correo FROM "Usuario" WHERE "idUsuario" = %s',
            (usuario_id,),
        )
        row = cursor.fetchone()
        return str(row[0]).strip() if row and row[0] else None
    except Exception as e:
        print(f"Error obteniendo correo de usuario: {e}")
        return None
    finally:
        cursor.close()
        conexion.close()


def obtener_reporte_escaneo(usuario_id, escaneo_id=None):
    """Obtiene datos consolidados del escaneo para generar reporte PDF."""
    conexion = conectar()
    if not conexion:
        return None

    cursor = conexion.cursor(cursor_factory=RealDictCursor)

    try:
        if escaneo_id:
            cursor.execute(
                '''
                SELECT e."idEscaneo", e.url_objetivo, e.fecha, u.username, u.correo
                FROM "Escaneo" e
                JOIN "Usuario" u ON e."idUsuario" = u."idUsuario"
                WHERE e."idEscaneo" = %s AND e."idUsuario" = %s
                LIMIT 1
                ''',
                (escaneo_id, usuario_id),
            )
        else:
            cursor.execute(
                '''
                SELECT e."idEscaneo", e.url_objetivo, e.fecha, u.username, u.correo
                FROM "Escaneo" e
                JOIN "Usuario" u ON e."idUsuario" = u."idUsuario"
                WHERE e."idUsuario" = %s
                ORDER BY e.fecha DESC
                LIMIT 1
                ''',
                (usuario_id,),
            )

        encabezado = cursor.fetchone()
        if not encabezado:
            return None

        cursor.execute(
            '''
            SELECT
                cv."Nombre" AS tipo,
                ns."Nombre" AS severidad,
                cv."Descripcion" AS descripcion,
                cv."Recomendacion" AS recomendacion,
                COALESCE(h.parametro, '') AS parametro,
                COALESCE(h.payload, '') AS payload
            FROM "hallazgo" h
            JOIN "catalogo_Vulnerabilidad" cv ON h."idVulnerabilidad" = cv."idvulnerabilidad"
            JOIN "niveles_severidad" ns ON ns."id_severidad" = COALESCE(h."idseveridad", cv."idseveridad")
            WHERE h."idEscaneo" = %s
            ORDER BY h."idHallazgo" ASC
            ''',
            (encabezado['idEscaneo'],),
        )
        hallazgos = [dict(row) for row in cursor.fetchall()]

        return {
            'escaneo_id': int(encabezado['idEscaneo']),
            'usuario': str(encabezado['username']),
            'correo': str(encabezado['correo']),
            'url': str(encabezado['url_objetivo']),
            'fecha': encabezado['fecha'],
            'protocolo': 'HTTPS' if str(encabezado['url_objetivo']).startswith('https://') else 'HTTP',
            'total_hallazgos': len(hallazgos),
            'hallazgos': hallazgos,
        }
    except Exception as e:
        print(f"Error obteniendo reporte de escaneo: {e}")
        return None
    finally:
        cursor.close()
        conexion.close()


def obtener_datos_dashboard():
    """Obtiene datos del dashboard con el nuevo esquema."""
    conexion = conectar()
    if not conexion:
        return None

    cursor = conexion.cursor()
    datos = {}

    try:
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN "inRol" = TRUE THEN 1 END) as nuevos
            FROM "Usuario"
        ''')
        row = cursor.fetchone()
        datos['usuarios'] = {'total': row[0], 'nuevos': row[1]}

        cursor.execute('''
            SELECT COUNT(*)
            FROM "hallazgo" h
            JOIN "catalogo_Vulnerabilidad" cv ON h."idVulnerabilidad" = cv."idvulnerabilidad"
            JOIN "niveles_severidad" ns ON ns."id_severidad" = COALESCE(h."idseveridad", cv."idseveridad")
            WHERE ns."Nombre" IN ('Critico', 'Alto')
        ''')
        datos['vulnerabilidades_criticas'] = cursor.fetchone()[0]

        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN fecha::date = CURRENT_DATE THEN 1 END) as hoy
            FROM "Escaneo"
        ''')
        row = cursor.fetchone()
        datos['links_escaneados'] = {'total': row[0], 'hoy': row[1]}

        cursor.execute('''
            SELECT 
                cv."Nombre",
                COUNT(h."idHallazgo") as frecuencia
            FROM "catalogo_Vulnerabilidad" cv
            LEFT JOIN "hallazgo" h ON cv."idvulnerabilidad" = h."idVulnerabilidad"
            GROUP BY cv."idvulnerabilidad", cv."Nombre"
            ORDER BY frecuencia DESC
        ''')
        datos['frecuencia_tipos'] = cursor.fetchall()

        cursor.execute('''
            SELECT 
                e.url_objetivo,
                e.fecha,
                COALESCE(MAX(CASE ns."Nombre"
                    WHEN 'Critico' THEN 4
                    WHEN 'Alto' THEN 3
                    WHEN 'Medio' THEN 2
                    WHEN 'Bajo' THEN 1
                    ELSE 0
                END), 0) AS severidad_rank,
                COUNT(h."idHallazgo") as total_hallazgos
            FROM "Escaneo" e
            LEFT JOIN "hallazgo" h ON e."idEscaneo" = h."idEscaneo"
            LEFT JOIN "catalogo_Vulnerabilidad" cv ON h."idVulnerabilidad" = cv."idvulnerabilidad"
            LEFT JOIN "niveles_severidad" ns ON ns."id_severidad" = COALESCE(h."idseveridad", cv."idseveridad")
            GROUP BY e."idEscaneo", e.url_objetivo, e.fecha
            ORDER BY e.fecha DESC
            LIMIT 20
        ''')

        escaneos_recientes = []
        for row in cursor.fetchall():
            if row[2] == 4:
                clase = 'bg-red-500/20 text-red-400'
                texto = 'Critico'
            elif row[2] == 3:
                clase = 'bg-orange-500/20 text-orange-400'
                texto = 'Alto'
            elif row[2] == 2:
                clase = 'bg-yellow-500/20 text-yellow-300'
                texto = 'Medio'
            elif row[2] == 1:
                clase = 'bg-sky-500/20 text-sky-300'
                texto = 'Bajo'
            else:
                clase = 'bg-emerald-500/20 text-emerald-400'
                texto = 'Sin riesgo'

            escaneos_recientes.append({
                'url': row[0],
                'fecha': row[1].strftime('%d/%m/%Y'),
                'hora': row[1].strftime('%H:%M'),
                'severidad_clase': clase,
                'severidad_texto': texto,
                'total': row[3]
            })

        datos['escaneos_recientes'] = escaneos_recientes

    except Exception as e:
        print(f"Error obteniendo datos del dashboard: {e}")
        return None
    finally:
        cursor.close()
        conexion.close()

    return datos


def obtener_historial_escaneos(usuario_id):
    """Obtiene el historial completo de escaneos para un usuario (VERSIÓN OPTIMIZADA)"""
    print(f"\n🔍 obtener_historial_escaneos - Usuario ID: {usuario_id}")

    conexion = conectar()
    if not conexion:
        print("❌ Error de conexión a BD")
        return []

    cursor = conexion.cursor(cursor_factory=RealDictCursor)
    try:
        # 1. Verificar usuario
        cursor.execute(
            'SELECT * FROM "Usuario" WHERE "idUsuario" = %s', (usuario_id,))
        usuario = cursor.fetchone()
        if not usuario:
            print(f"❌ Usuario {usuario_id} no existe")
            return []

        print(f"✅ Usuario encontrado: {usuario['username']}")

        # 2. Obtener escaneos básicos (sin joins pesados)
        cursor.execute('''
            SELECT 
                e."idEscaneo",
                e.url_objetivo as url,
                CASE 
                    WHEN e.url_objetivo LIKE 'https://%%' THEN 'HTTPS'
                    ELSE 'HTTP'
                END as protocolo,
                e.fecha
            FROM "Escaneo" e
            WHERE e."idUsuario" = %s
            ORDER BY e.fecha DESC
        ''', (usuario_id,))

        escaneos = cursor.fetchall()
        print(f"📊 Escaneos encontrados: {len(escaneos)}")

        if not escaneos:
            print("⚠️ No hay escaneos para este usuario")
            return []

        # 3. Para cada escaneo, obtener sus hallazgos (consulta separada)
        historial = []
        for escaneo in escaneos:
            try:
                escaneo_id = escaneo['idEscaneo']

                # Obtener hallazgos para este escaneo
                cursor.execute('''
                    SELECT 
                        cv."Nombre" as tipo_vuln,
                        ns."Nombre" as severidad
                    FROM "hallazgo" h
                    JOIN "catalogo_Vulnerabilidad" cv ON h."idVulnerabilidad" = cv."idvulnerabilidad"
                    JOIN "niveles_severidad" ns ON ns."id_severidad" = COALESCE(h."idseveridad", cv."idseveridad")
                    WHERE h."idEscaneo" = %s
                ''', (escaneo_id,))

                hallazgos = cursor.fetchall()

                # Procesar hallazgos
                tipos = [h['tipo_vuln'] for h in hallazgos if h['tipo_vuln']]
                severidades = [h['severidad']
                               for h in hallazgos if h['severidad']]

                total_vuln = len(hallazgos)

                # Determinar severidad máxima
                if 'Critico' in severidades:
                    max_severidad = 'Critico'
                    clase_badge = 'bg-red-600'
                elif 'Alto' in severidades:
                    max_severidad = 'Alto'
                    clase_badge = 'bg-red-600'
                elif 'Medio' in severidades:
                    max_severidad = 'Medio'
                    clase_badge = 'bg-orange-500'
                elif 'Bajo' in severidades:
                    max_severidad = 'Bajo'
                    clase_badge = 'bg-green-600'
                else:
                    max_severidad = 'Sin riesgo'
                    clase_badge = 'bg-green-600'

                # Tipos de vulnerabilidad
                tipos_str = ', '.join(set(tipos)) if tipos else 'Ninguna'

                # Formatear fecha
                fecha_obj = escaneo['fecha']
                fecha_str = fecha_obj.strftime(
                    '%d/%m/%Y') if fecha_obj else '00/00/0000'
                hora_str = fecha_obj.strftime(
                    '%H:%M') if fecha_obj else '00:00'

                historial.append({
                    'id': escaneo_id,
                    'url': escaneo['url'],
                    'protocolo': escaneo['protocolo'],
                    'fecha': fecha_str,
                    'hora': hora_str,
                    'total_vuln': total_vuln,
                    'tipos_vuln': tipos_str,
                    'severidad': max_severidad,
                    'clase_badge': clase_badge
                })

            except Exception as e:
                print(f"❌ Error procesando escaneo {escaneo_id}: {e}")
                continue

        print(f"✅ Historial formateado: {len(historial)} escaneos")
        return historial

    except Exception as e:
        print(f"❌ Error en obtener_historial_escaneos: {e}")
        import traceback
        traceback.print_exc()
        return []
    finally:
        cursor.close()
        conexion.close()


# ============================================
# FUNCIONES PARA CONFIGURACIÓN Y ADMINISTRACIÓN
# ============================================

def obtener_usuario_por_id(usuario_id):
    """Obtiene los datos de un usuario por su ID"""
    conexion = conectar()
    if not conexion:
        return None

    cursor = conexion.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute('''
            SELECT 
                "idUsuario" AS id,
                username AS usuario,
                correo AS email,
                password_hash AS contrasena_hash,
                "inRol" AS activo
            FROM "Usuario"
            WHERE "idUsuario" = %s
        ''', (usuario_id,))

        row = cursor.fetchone()
        return dict(row) if row else None
    except Exception as e:
        print(f"Error obteniendo usuario por ID: {e}")
        return None
    finally:
        cursor.close()
        conexion.close()


def existe_usuario(usuario, usuario_id_excluir=None):
    """Verifica si ya existe un usuario con ese nombre, excluyendo opcionalmente un ID"""
    conexion = conectar()
    if not conexion:
        return False

    cursor = conexion.cursor()
    try:
        if usuario_id_excluir:
            cursor.execute(
                'SELECT 1 FROM "Usuario" WHERE username = %s AND "idUsuario" != %s',
                (usuario, usuario_id_excluir)
            )
        else:
            cursor.execute(
                'SELECT 1 FROM "Usuario" WHERE username = %s',
                (usuario,)
            )
        return cursor.fetchone() is not None
    except Exception as e:
        print(f"Error verificando usuario: {e}")
        return False
    finally:
        cursor.close()
        conexion.close()


def existe_email(email, usuario_id_excluir=None):
    """Verifica si ya existe un usuario con ese email, excluyendo opcionalmente un ID"""
    conexion = conectar()
    if not conexion:
        return False

    cursor = conexion.cursor()
    try:
        if usuario_id_excluir:
            cursor.execute(
                'SELECT 1 FROM "Usuario" WHERE correo = %s AND "idUsuario" != %s',
                (email, usuario_id_excluir)
            )
        else:
            cursor.execute(
                'SELECT 1 FROM "Usuario" WHERE correo = %s',
                (email,)
            )
        return cursor.fetchone() is not None
    except Exception as e:
        print(f"Error verificando email: {e}")
        return False
    finally:
        cursor.close()
        conexion.close()


def actualizar_usuario(usuario_id, campo, valor):
    """Actualiza un campo del usuario (username o email)"""
    conexion = conectar()
    if not conexion:
        return False

    cursor = conexion.cursor()
    try:
        if campo == 'usuario':
            cursor.execute(
                'UPDATE "Usuario" SET username = %s WHERE "idUsuario" = %s',
                (valor, usuario_id)
            )
        elif campo == 'email':
            cursor.execute(
                'UPDATE "Usuario" SET correo = %s WHERE "idUsuario" = %s',
                (valor, usuario_id)
            )
        else:
            return False

        conexion.commit()
        return cursor.rowcount > 0
    except Exception as e:
        conexion.rollback()
        print(f"Error actualizando usuario: {e}")
        return False
    finally:
        cursor.close()
        conexion.close()


def actualizar_contrasena(usuario_id, nuevo_hash):
    """Actualiza la contraseña del usuario"""
    conexion = conectar()
    if not conexion:
        return False

    cursor = conexion.cursor()
    try:
        cursor.execute(
            'UPDATE "Usuario" SET password_hash = %s WHERE "idUsuario" = %s',
            (nuevo_hash, usuario_id)
        )
        conexion.commit()
        return cursor.rowcount > 0
    except Exception as e:
        conexion.rollback()
        print(f"Error actualizando contraseña: {e}")
        return False
    finally:
        cursor.close()
        conexion.close()


if __name__ == '__main__':
    inicializar_db()
    print("\nProbando conexion y datos...")
    datos = obtener_datos_dashboard()
    if datos:
        print(f"Dashboard data cargado: {len(datos)} categorias")
        print(f"Usuarios: {datos['usuarios']['total']}")
        print(
            f"Vulnerabilidades criticas: {datos['vulnerabilidades_criticas']}")
        print(f"Total escaneos: {datos['links_escaneados']['total']}")
        print(f"Escaneos hoy: {datos['links_escaneados']['hoy']}")
