import os
import psycopg2

# Configuración híbrida (Laptop vs Docker)
DB_CONFIG = {
    # os.getenv("VARIABLE", "VALOR_POR_DEFECTO")
    "dbname": os.getenv("DB_NAME", "vulnshield_db"),
    "user": os.getenv("DB_USER", "jade"),
    "password": os.getenv("DB_PASSWORD", "123456"),

    # Si detecta que está en Docker, usará 'db'. Si no, usará 'localhost'
    "host": os.getenv("DB_HOST", "localhost"),

    # Si detecta que está en Docker, usará '5432'. Si no, usará '5433' (tu puerto local)
    "port": os.getenv("DB_PORT", "5433")
}


def conectar():
    try:
        return psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        # Esto te dirá exactamente a qué host está intentando conectar
        print(f"Error de base de datos (Host: {DB_CONFIG.get('host')}): {e}")
        return None


def inicializar_db():
    conexion = conectar()
    if conexion:
        cursor = conexion.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hallazgos (
                id SERIAL PRIMARY KEY,
                url TEXT NOT NULL,
                tipo_vulnerabilidad VARCHAR(100),
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conexion.commit()
        cursor.close()
        conexion.close()
        print("Base de datos lista.")


def guardar_hallazgo(url, tipo):
    conexion = conectar()
    if conexion:
        cursor = conexion.cursor()
        cursor.execute(
            'INSERT INTO hallazgos (url, tipo_vulnerabilidad) VALUES (%s, %s)', (url, tipo))
        conexion.commit()
        cursor.close()
        conexion.close()


if __name__ == '__main__':
    inicializar_db()
