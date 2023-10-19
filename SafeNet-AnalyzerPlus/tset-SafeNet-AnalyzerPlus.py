import sqlite3

# Conectar a la base de datos
conn = sqlite3.connect('captured_data.db')
cursor = conn.cursor()

# Consultar la tabla captured_packets
cursor.execute('SELECT * FROM captured_packets')
rows = cursor.fetchall()

if len(rows) > 0:
    print("Se han almacenado datos en la base de datos:")
    for row in rows:
        print(row)
else:
    print("No se han encontrado datos en la base de datos.")

# Cerrar la conexión
conn.close()

