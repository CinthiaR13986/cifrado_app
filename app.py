from flask import Flask, render_template, request, redirect, session
import sqlite3
import base64
import uuid
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret123"

# Conexión a SQLite
def get_db():
    return sqlite3.connect("database.db")

# Inicializar base de datos
def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Usuarios
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT,
        correo TEXT UNIQUE,
        password TEXT
    )
    """)

    # Mensajes cifrados
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mensajes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_usuario INTEGER,
        texto_original TEXT,
        texto_cifrado TEXT,
        token TEXT,
        fecha TEXT
    )
    """)

    # Historial de intentos de descifrado
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS historial_accesos(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_usuario INTEGER,
        token TEXT,
        fecha TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# Funciones de cifrado/descifrado
def cifrar(texto):
    return base64.b64encode(texto.encode()).decode()

def descifrar(texto):
    return base64.b64decode(texto.encode()).decode()

# Rutas
@app.route("/")
def home():
    return render_template("login.html")

@app.route("/registro", methods=["GET","POST"])
def registro():
    if request.method == "POST":
        nombre = request.form["nombre"]
        correo = request.form["correo"]
        password = request.form["password"]
        password_hash = generate_password_hash(password)

        conn = get_db()
        try:
            conn.execute("INSERT INTO usuarios(nombre, correo, password) VALUES(?,?,?)",
                         (nombre, correo, password_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Correo ya registrado"
        conn.close()
        return redirect("/")
    return render_template("registro.html")

@app.route("/login", methods=["POST"])
def login():
    correo = request.form["correo"]
    password = request.form["password"]

    conn = get_db()
    cursor = conn.execute("SELECT * FROM usuarios WHERE correo=?", (correo,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[3], password):
        session["user_id"] = user[0]
        session["user_name"] = user[1]
        return redirect("/dashboard")
    return "Credenciales incorrectas"

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dashboard", methods=["GET","POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    if request.method == "POST":
        texto = request.form["texto"]
        texto_cifrado = cifrar(texto)
        token = str(uuid.uuid4())
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        conn.execute("INSERT INTO mensajes(id_usuario, texto_original, texto_cifrado, token, fecha) VALUES(?,?,?,?,?)",
                     (session["user_id"], texto, texto_cifrado, token, fecha))
        conn.commit()
        conn.close()

        return render_template("resultado.html", token=token)

    return render_template("dashboard.html")

@app.route("/buscar", methods=["GET","POST"])
def buscar():
    if "user_id" not in session:
        return redirect("/")

    if request.method == "POST":
        token = request.form["token"]

        conn = get_db()
        cursor = conn.execute("SELECT * FROM mensajes WHERE token=?", (token,))
        data = cursor.fetchone()

        if data:
            texto = descifrar(data[3])
            fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Registrar intento de descifrado
            conn.execute("INSERT INTO historial_accesos(id_usuario, token, fecha) VALUES(?,?,?)",
                         (session["user_id"], token, fecha))
            conn.commit()
            conn.close()
            return f"Texto: {texto} <br> Usuario ID: {data[1]} <br> Fecha: {data[5]}"
        conn.close()
        return "No encontrado"

    return """
    <form method='POST'>
      Token: <input type='text' name='token'>
      <button type='submit'>Buscar</button>
    </form>
    """

@app.route("/historial")
def historial():
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()

    # Mensajes enviados
    cursor = conn.execute(
        "SELECT token, texto_original, fecha, nombre FROM mensajes INNER JOIN usuarios ON id_usuario = usuarios.id WHERE id_usuario=?",
        (session["user_id"],)
    )
    datos = cursor.fetchall()

    # Intentos de descifrado
    cursor2 = conn.execute(
        "SELECT token, fecha, nombre FROM usuarios INNER JOIN historial_accesos ON usuarios.id = historial_accesos.id_usuario WHERE id_usuario=?",
        (session["user_id"],)
    )
    accesos = cursor2.fetchall()

    conn.close()

    return render_template("historial.html", datos=datos, accesos=accesos)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
