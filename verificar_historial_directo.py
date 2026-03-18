# verificar_historial_directo.py
from base_datos import obtener_historial_escaneos, conectar

def verificar_directo():
    print("="*60)
    print("🔍 VERIFICACIÓN DIRECTA DEL HISTORIAL")
    print("="*60)
    
    # 1. Ver usuarios
    conn = conectar()
    cur = conn.cursor()
    cur.execute('SELECT "idUsuario", username FROM "Usuario"')
    usuarios = cur.fetchall()
    print(f"\n👤 Usuarios disponibles:")
    for u in usuarios:
        print(f"   ID: {u[0]}, Usuario: {u[1]}")
    
    # 2. Ver escaneos directamente
    print(f"\n🔍 ESCANEOS EN BD (vista directa):")
    cur.execute('''
        SELECT e."idEscaneo", e."idUsuario", u.username, e.url_objetivo, e.fecha
        FROM "Escaneo" e
        JOIN "Usuario" u ON e."idUsuario" = u."idUsuario"
        ORDER BY e.fecha DESC
    ''')
    escaneos = cur.fetchall()
    for e in escaneos:
        print(f"   ID:{e[0]}, Usuario:{e[2]}, URL:{e[3][:30]}...")
    
    # 3. Probar historial para cada usuario
    for u in usuarios:
        usuario_id = u[0]
        username = u[1]
        print(f"\n📊 Probando historial para {username} (ID: {usuario_id})")
        
        historial = obtener_historial_escaneos(usuario_id)
        
        if historial:
            print(f"   ✅ {len(historial)} escaneos encontrados:")
            for h in historial:
                print(f"      • ID: {h['id']} - {h['url'][:30]}... - {h['total_vuln']} vuln")
        else:
            print(f"   ❌ No se encontraron escaneos")
    
    cur.close()
    conn.close()

if __name__ == "__main__":
    verificar_directo()