# verificar_escaneos.py
import psycopg2
from psycopg2.extras import RealDictCursor
from base_datos import conectar

def verificar_escaneos():
    """Verifica que los escaneos se estén guardando correctamente"""
    conexion = conectar()
    if not conexion:
        print("❌ No se pudo conectar a la BD")
        return
    
    cursor = conexion.cursor(cursor_factory=RealDictCursor)
    
    try:
        # 1. Ver todos los usuarios
        cursor.execute('SELECT * FROM "Usuario"')
        usuarios = cursor.fetchall()
        print(f"\n👤 USUARIOS EN BD:")
        for u in usuarios:
            print(f"   ID: {u['idUsuario']}, Usuario: {u['username']}, Admin: {u['inRol']}")
        
        # 2. Ver todos los escaneos
        cursor.execute('''
            SELECT e.*, u.username 
            FROM "Escaneo" e
            JOIN "Usuario" u ON e."idUsuario" = u."idUsuario"
            ORDER BY e.fecha DESC
        ''')
        escaneos = cursor.fetchall()
        print(f"\n🔍 ESCANEOS EN BD: {len(escaneos)} encontrados")
        for e in escaneos:
            print(f"   ID: {e['idEscaneo']}, Usuario: {e['username']}, URL: {e['url_objetivo'][:50]}...")
        
        # 3. Ver hallazgos
        cursor.execute('SELECT COUNT(*) as count FROM "hallazgo"')
        hallazgos = cursor.fetchone()
        print(f"\n🛡️ HALLAZGOS EN BD: {hallazgos['count'] if hallazgos else 0}")
        
        # 4. Probar la función de historial específicamente
        print(f"\n📊 PROBANDO FUNCIÓN obtener_historial_escaneos:")
        from base_datos import obtener_historial_escaneos
        for u in usuarios:
            historial = obtener_historial_escaneos(u['idUsuario'])
            print(f"   Usuario {u['username']} (ID: {u['idUsuario']}): {len(historial)} escaneos en historial")
            for h in historial:
                print(f"      - {h['url']} - {h['fecha']} - {h['total_vuln']} vuln")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cursor.close()
        conexion.close()

if __name__ == "__main__":
    verificar_escaneos()