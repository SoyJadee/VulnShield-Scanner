import os
import psycopg2
from datetime import datetime

# Configuración híbrida (Laptop vs Docker)
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "vulnshield_db"),
    "user": os.getenv("DB_USER", "jade"),
    "password": os.getenv("DB_PASSWORD", "123456"),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432")
}


def conectar():
    """Establece conexión con la base de datos"""
    try:
        return psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        print(f"❌ Error de base de datos (Host: {DB_CONFIG.get('host')}): {e}")
        return None


def verificar_y_reconstruir_hallazgos(cursor):
    """
    Verifica si la tabla hallazgos tiene la estructura correcta
    Si no, la reconstruye conservando los datos
    """
    # Verificar si la tabla existe
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = 'hallazgos'
        )
    """)
    tabla_existe = cursor.fetchone()[0]
    
    if not tabla_existe:
        print("🆕 Tabla hallazgos no existe. Se creará desde cero.")
        return False
    
    # Verificar columnas actuales
    cursor.execute("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'hallazgos'
    """)
    columnas_actuales = [col[0] for col in cursor.fetchall()]
    
    # Columnas que debería tener la versión 4NF
    columnas_correctas = ['id', 'analisis_id', 'tipo_vulnerabilidad_id', 
                          'url_especifica', 'parametro', 'payload', 'fecha_deteccion']
    
    # Verificar si tiene la estructura vieja (sin analisis_id)
    if 'analisis_id' not in columnas_actuales:
        print("⚠️ Detectada tabla hallazgos con estructura antigua. Reconstruyendo...")
        
        # Guardar datos existentes
        cursor.execute("SELECT COUNT(*) FROM hallazgos")
        total_registros = cursor.fetchone()[0]
        print(f"📦 Respaldando {total_registros} registros existentes...")
        
        # Crear tabla temporal con los datos
        cursor.execute("""
            CREATE TEMPORARY TABLE hallazgos_backup AS 
            SELECT * FROM hallazgos
        """)
        
        # Determinar qué columnas tiene el backup
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'hallazgos_backup'
        """)
        columnas_backup = [col[0] for col in cursor.fetchall()]
        print(f"📊 Columnas en backup: {', '.join(columnas_backup)}")
        
        # Eliminar tabla vieja
        cursor.execute("DROP TABLE hallazgos CASCADE")
        
        # Crear tabla nueva con estructura correcta
        cursor.execute('''
            CREATE TABLE hallazgos (
                id SERIAL PRIMARY KEY,
                analisis_id INTEGER,
                tipo_vulnerabilidad_id INTEGER,
                url_especifica TEXT,
                parametro TEXT,
                payload TEXT,
                fecha_deteccion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Restaurar datos desde backup
        if 'url' in columnas_backup:
            if 'fecha' in columnas_backup and 'tipo_vulnerabilidad' in columnas_backup:
                cursor.execute('''
                    INSERT INTO hallazgos (url_especifica, fecha_deteccion)
                    SELECT url, fecha FROM hallazgos_backup
                ''')
                print(f"✅ Restaurados {cursor.rowcount} registros (url y fecha)")
            elif 'fecha' in columnas_backup:
                cursor.execute('''
                    INSERT INTO hallazgos (url_especifica, fecha_deteccion)
                    SELECT url, fecha FROM hallazgos_backup
                ''')
                print(f"✅ Restaurados {cursor.rowcount} registros (con fecha)")
            else:
                cursor.execute('''
                    INSERT INTO hallazgos (url_especifica, fecha_deteccion)
                    SELECT url, CURRENT_TIMESTAMP FROM hallazgos_backup
                ''')
                print(f"✅ Restaurados {cursor.rowcount} registros (sin fecha)")
        
        # Limpiar tabla temporal
        cursor.execute("DROP TABLE IF EXISTS hallazgos_backup")
        
        return True  # Indica que se reconstruyó
    
    return False  # No necesitó reconstrucción


def inicializar_db():
    """Crea todas las tablas en 4NF y datos iniciales"""
    conexion = conectar()
    if not conexion:
        return

    cursor = conexion.cursor()
    
    print("🔄 Verificando/Creando tablas en 4NF...")
    
    # ============================================
    # VERIFICAR Y RECONSTRUIR HALLAZGOS SI ES NECESARIO
    # ============================================
    reconstruida = verificar_y_reconstruir_hallazgos(cursor)
    if reconstruida:
        print("✅ Tabla hallazgos reconstruida correctamente")
    
    # ============================================
    # 1. TABLAS CATÁLOGO (INDEPENDIENTES)
    # ============================================
    
    # Tabla de protocolos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS protocolos (
            id SERIAL PRIMARY KEY,
            nombre VARCHAR(5) UNIQUE NOT NULL,
            descripcion VARCHAR(50),
            puerto INTEGER
        )
    ''')
    
    # Tabla de tipos de vulnerabilidad (SOLO SQLi y XSS)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tipos_vulnerabilidad (
            id SERIAL PRIMARY KEY,
            nombre_amenaza VARCHAR(50) UNIQUE NOT NULL,
            nivel_amenaza VARCHAR(20) NOT NULL,
            color_hex VARCHAR(7) DEFAULT '#FF4444',
            CHECK (nivel_amenaza IN ('Crítico', 'Alto', 'Medio', 'Bajo'))
        )
    ''')
    
    # Tabla de administradores
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS administradores (
            id_administrador SERIAL PRIMARY KEY,
            usuario VARCHAR(50) UNIQUE NOT NULL,
            contrasena_hash VARCHAR(255) NOT NULL,
            email VARCHAR(100) UNIQUE,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ultimo_acceso TIMESTAMP,
            activo BOOLEAN DEFAULT TRUE
        )
    ''')
    
    # Tabla principal de análisis
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analisis (
            id SERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            fecha_analisis DATE NOT NULL,
            hora_analisis TIME NOT NULL,
            protocolo_id INTEGER REFERENCES protocolos(id),
            administrador_id INTEGER REFERENCES administradores(id_administrador),
            tiempo_ejecucion FLOAT,
            estado VARCHAR(20) DEFAULT 'completado'
        )
    ''')
    
    # Si hallazgos no se reconstruyó, asegurar que tenga la estructura correcta
    if not reconstruida:
        # Agregar columnas faltantes si es necesario
        cursor.execute('''
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='hallazgos' AND column_name='analisis_id') THEN
                    ALTER TABLE hallazgos ADD COLUMN analisis_id INTEGER;
                END IF;
                
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='hallazgos' AND column_name='tipo_vulnerabilidad_id') THEN
                    ALTER TABLE hallazgos ADD COLUMN tipo_vulnerabilidad_id INTEGER;
                END IF;
                
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='hallazgos' AND column_name='url_especifica') THEN
                    ALTER TABLE hallazgos ADD COLUMN url_especifica TEXT;
                END IF;
                
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='hallazgos' AND column_name='parametro') THEN
                    ALTER TABLE hallazgos ADD COLUMN parametro TEXT;
                END IF;
                
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='hallazgos' AND column_name='payload') THEN
                    ALTER TABLE hallazgos ADD COLUMN payload TEXT;
                END IF;
                
                IF EXISTS (SELECT 1 FROM information_schema.columns 
                          WHERE table_name='hallazgos' AND column_name='fecha') 
                   AND NOT EXISTS (SELECT 1 FROM information_schema.columns 
                                  WHERE table_name='hallazgos' AND column_name='fecha_deteccion') THEN
                    ALTER TABLE hallazgos RENAME COLUMN fecha TO fecha_deteccion;
                END IF;
                
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='hallazgos' AND column_name='fecha_deteccion') THEN
                    ALTER TABLE hallazgos ADD COLUMN fecha_deteccion TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
                END IF;
            END $$;
        ''')
    
    # ============================================
    # AGREGAR RELACIONES (FOREIGN KEYS)
    # ============================================
    
    cursor.execute('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint 
                WHERE conname = 'hallazgos_analisis_id_fkey'
            ) THEN
                ALTER TABLE hallazgos 
                ADD CONSTRAINT hallazgos_analisis_id_fkey 
                FOREIGN KEY (analisis_id) REFERENCES analisis(id) ON DELETE CASCADE;
            END IF;
        END $$;
    ''')
    
    cursor.execute('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint 
                WHERE conname = 'hallazgos_tipo_vulnerabilidad_id_fkey'
            ) THEN
                ALTER TABLE hallazgos 
                ADD CONSTRAINT hallazgos_tipo_vulnerabilidad_id_fkey 
                FOREIGN KEY (tipo_vulnerabilidad_id) REFERENCES tipos_vulnerabilidad(id);
            END IF;
        END $$;
    ''')
    
    # ============================================
    # ÍNDICES
    # ============================================
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_hallazgos_analisis ON hallazgos(analisis_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_hallazgos_fecha ON hallazgos(fecha_deteccion)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_analisis_fecha ON analisis(fecha_analisis)')
    
    # ============================================
    # DATOS INICIALES (CATÁLOGOS)
    # ============================================
    
    # Insertar protocolos
    cursor.execute('''
        INSERT INTO protocolos (nombre, descripcion, puerto) VALUES
        ('HTTP', 'Protocolo no seguro', 80),
        ('HTTPS', 'Protocolo seguro con SSL/TLS', 443)
        ON CONFLICT (nombre) DO NOTHING
    ''')
    
    # Insertar tipos de vulnerabilidad (SOLO SQLi y XSS)
    vulnerabilidades = [
        ('SQL Injection', 'Crítico', '#FF4444'),
        ('XSS', 'Alto', '#FF8800')
    ]
    
    for nombre, nivel, color in vulnerabilidades:
        cursor.execute('''
            INSERT INTO tipos_vulnerabilidad (nombre_amenaza, nivel_amenaza, color_hex) 
            VALUES (%s, %s, %s) ON CONFLICT (nombre_amenaza) DO NOTHING
        ''', (nombre, nivel, color))
    
    # Insertar administrador por defecto (contraseña: admin123)
    cursor.execute('''
        INSERT INTO administradores (usuario, contrasena_hash, email) 
        VALUES (%s, %s, %s) 
        ON CONFLICT (usuario) DO NOTHING
    ''', ('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4LhGqgHqSO', 'admin@vulnshield.com'))
    
    # ============================================
    # MIGRAR DATOS EXISTENTES A LA NUEVA ESTRUCTURA
    # ============================================
    
    # Crear análisis para URLs existentes (si no existen)
    cursor.execute('''
        INSERT INTO analisis (url, fecha_analisis, hora_analisis, administrador_id)
        SELECT DISTINCT 
            h.url_especifica,
            CURRENT_DATE,
            CURRENT_TIME,
            1
        FROM hallazgos h
        WHERE h.url_especifica IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM analisis a WHERE a.url = h.url_especifica)
        ON CONFLICT DO NOTHING
    ''')
    
    # Actualizar analisis_id en hallazgos
    cursor.execute('''
        UPDATE hallazgos h
        SET analisis_id = a.id
        FROM analisis a
        WHERE h.url_especifica = a.url AND h.analisis_id IS NULL
    ''')
    
    # ============================================
    # NOTA: Ya no intentamos migrar tipo_vulnerabilidad
    # porque la columna ya no existe
    # Los nuevos escaneos ya guardarán el ID correctamente
    # ============================================
    
    conexion.commit()
    
    # ============================================
    # VERIFICACIÓN FINAL
    # ============================================
    
    cursor.execute("""
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'hallazgos'
        ORDER BY ordinal_position
    """)
    
    print("\n✅ ESTRUCTURA FINAL DE HALLAZGOS:")
    columnas = []
    for col in cursor.fetchall():
        columnas.append(col[0])
        print(f"   • {col[0]}: {col[1]}")
    
    cursor.execute("SELECT COUNT(*) FROM hallazgos")
    total = cursor.fetchone()[0]
    print(f"\n📊 Total registros en hallazgos: {total}")
    print(f"📋 Columnas: {', '.join(columnas)}")
    
    cursor.close()
    conexion.close()
    print("\n✅ Base de datos inicializada correctamente en 4NF")


def guardar_analisis_completo(url, protocolo, administrador_id, hallazgos_list, tiempo_ejecucion=0):
    """
    Guarda un análisis completo con todos sus hallazgos
    """
    conexion = conectar()
    if not conexion:
        return None
    
    cursor = conexion.cursor()
    
    try:
        ahora = datetime.now()
        
        # 1. Obtener ID del protocolo
        cursor.execute('SELECT id FROM protocolos WHERE nombre = %s', (protocolo,))
        resultado = cursor.fetchone()
        if not resultado:
            cursor.execute('INSERT INTO protocolos (nombre) VALUES (%s) RETURNING id', (protocolo,))
            protocolo_id = cursor.fetchone()[0]
        else:
            protocolo_id = resultado[0]
        
        # 2. Insertar en analisis
        cursor.execute('''
            INSERT INTO analisis 
            (url, fecha_analisis, hora_analisis, protocolo_id, administrador_id, tiempo_ejecucion)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            url,
            ahora.date(),
            ahora.time(),
            protocolo_id,
            administrador_id,
            tiempo_ejecucion
        ))
        
        analisis_id = cursor.fetchone()[0]
        
        # 3. Guardar cada hallazgo
        for hallazgo in hallazgos_list:
            # Obtener ID del tipo de vulnerabilidad
            cursor.execute('SELECT id FROM tipos_vulnerabilidad WHERE nombre_amenaza = %s', (hallazgo['tipo'],))
            resultado = cursor.fetchone()
            
            if resultado:
                vuln_id = resultado[0]
                
                # Insertar hallazgo
                cursor.execute('''
                    INSERT INTO hallazgos 
                    (analisis_id, tipo_vulnerabilidad_id, url_especifica, parametro, payload)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (
                    analisis_id,
                    vuln_id,
                    hallazgo.get('url_especifica', url),
                    hallazgo.get('parametro', ''),
                    hallazgo.get('payload', '')
                ))
        
        conexion.commit()
        print(f"✅ Análisis #{analisis_id} guardado con {len(hallazgos_list)} hallazgos")
        return analisis_id
        
    except Exception as e:
        conexion.rollback()
        print(f"❌ Error guardando análisis: {e}")
        return None
    finally:
        cursor.close()
        conexion.close()


def guardar_hallazgo(url, tipo):
    """
    Función de compatibilidad con el código existente
    """
    protocolo = 'HTTPS' if url.startswith('https') else 'HTTP'
    
    # Limpiar el tipo
    if 'SQL' in tipo:
        tipo_limpio = 'SQL Injection'
    elif 'XSS' in tipo:
        tipo_limpio = 'XSS'
    else:
        tipo_limpio = tipo.split(' - ')[0] if ' - ' in tipo else tipo
    
    hallazgos = [{
        'tipo': tipo_limpio,
        'url_especifica': url,
        'parametro': '',
        'payload': ''
    }]
    
    return guardar_analisis_completo(
        url=url,
        protocolo=protocolo,
        administrador_id=1,  # Admin por defecto
        hallazgos_list=hallazgos,
        tiempo_ejecucion=0
    )


def obtener_datos_dashboard():
    """Obtiene todos los datos necesarios para el dashboard admin"""
    conexion = conectar()
    if not conexion:
        return None
    
    cursor = conexion.cursor()
    datos = {}
    
    try:
        # 1. Total de administradores
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN fecha_registro > NOW() - INTERVAL '30 days' THEN 1 END) as nuevos
            FROM administradores
        ''')
        row = cursor.fetchone()
        datos['usuarios'] = {'total': row[0], 'nuevos': row[1]}
        
        # 2. Vulnerabilidades críticas (Críticas + Altas)
        cursor.execute('''
            SELECT COUNT(*)
            FROM hallazgos h
            JOIN tipos_vulnerabilidad tv ON h.tipo_vulnerabilidad_id = tv.id
            WHERE tv.nivel_amenaza IN ('Crítico', 'Alto')
        ''')
        datos['vulnerabilidades_criticas'] = cursor.fetchone()[0]
        
        # 3. Total links escaneados
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN fecha_analisis = CURRENT_DATE THEN 1 END) as hoy
            FROM analisis
        ''')
        row = cursor.fetchone()
        datos['links_escaneados'] = {'total': row[0], 'hoy': row[1]}
        
        # 4. Frecuencia por tipo (para gráfica de pastel)
        cursor.execute('''
            SELECT 
                tv.nombre_amenaza,
                COUNT(h.id) as frecuencia
            FROM tipos_vulnerabilidad tv
            LEFT JOIN hallazgos h ON tv.id = h.tipo_vulnerabilidad_id
            WHERE tv.nombre_amenaza IN ('SQL Injection', 'XSS')
            GROUP BY tv.id, tv.nombre_amenaza
            ORDER BY frecuencia DESC
        ''')
        datos['frecuencia_tipos'] = cursor.fetchall()
        
        # 5. Escaneos recientes
        cursor.execute('''
            SELECT 
                a.url,
                a.fecha_analisis,
                a.hora_analisis,
                MAX(tv.nivel_amenaza) as max_severidad,
                COUNT(h.id) as total_hallazgos
            FROM analisis a
            LEFT JOIN hallazgos h ON a.id = h.analisis_id
            LEFT JOIN tipos_vulnerabilidad tv ON h.tipo_vulnerabilidad_id = tv.id
            GROUP BY a.id, a.url, a.fecha_analisis, a.hora_analisis
            ORDER BY a.fecha_analisis DESC, a.hora_analisis DESC
            LIMIT 20
        ''')
        
        escaneos_recientes = []
        for row in cursor.fetchall():
            severidad = row[3] if row[3] else 'Sin riesgo'
            
            # Mapear severidad a clase CSS
            if severidad == 'Crítico':
                clase = 'bg-red-500/20 text-red-400'
                texto = 'Crítico'
            elif severidad == 'Alto':
                clase = 'bg-orange-500/20 text-orange-400'
                texto = 'Alto'
            elif severidad == 'Medio':
                clase = 'bg-yellow-500/20 text-yellow-300'
                texto = 'Medio'
            elif severidad == 'Bajo':
                clase = 'bg-sky-500/20 text-sky-300'
                texto = 'Bajo'
            else:
                clase = 'bg-emerald-500/20 text-emerald-400'
                texto = 'Sin riesgo'
            
            escaneos_recientes.append({
                'url': row[0],
                'fecha': row[1].strftime('%d/%m/%Y'),
                'hora': row[2].strftime('%H:%M'),
                'severidad_clase': clase,
                'severidad_texto': texto,
                'total': row[4]
            })
        
        datos['escaneos_recientes'] = escaneos_recientes
        
    except Exception as e:
        print(f"❌ Error obteniendo datos del dashboard: {e}")
        return None
    finally:
        cursor.close()
        conexion.close()
    
    return datos


if __name__ == '__main__':
    inicializar_db()
    print("\n📊 Probando conexión y datos...")
    datos = obtener_datos_dashboard()
    if datos:
        print(f"✅ Dashboard data cargado: {len(datos)} categorías")
        print(f"   • Usuarios: {datos['usuarios']['total']}")
        print(f"   • Vulnerabilidades críticas: {datos['vulnerabilidades_criticas']}")
        print(f"   • Total escaneos: {datos['links_escaneados']['total']}")
        print(f"   • Escaneos hoy: {datos['links_escaneados']['hoy']}")