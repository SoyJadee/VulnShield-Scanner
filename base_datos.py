import psycopg2

DB_CONFIG = {
    "dbname": "vulnshield_db",
    "user": "jade",
    "password": "123456",
    "host": "localhost",
    "port": "5433"
}


def conectar():
    try:
        return psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        print(f"Error de base de datos: {e}")
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
