"""""import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILIDAD 2: secreto débil y escrito en el código
SECRET = "secret123"

# "Base de datos" en memoria
USUARIOS = {
    "alumno": {"password": "alumno123", "role": "user"},
    "admin": {"password": "Xk9#mP2$vL7qW4nZ", "role": "admin"},
}


def verificar_token():
 
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):]
    try:
        # PARCHE: el servidor decide el algoritmo, no el token
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


@app.post("/login")
def login():
    datos = request.get_json(silent=True) or {}
    nombre = datos.get("usuario")
    usuario = USUARIOS.get(nombre)
    if not usuario or usuario["password"] != datos.get("password"):
        return jsonify(error="Credenciales inválidas"), 401
    # VULNERABILIDAD 3: el token no tiene fecha de expiración
    payload = {"sub": nombre, "role": usuario["role"]}
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    return jsonify(token=token)


@app.get("/perfil")
def perfil():
    payload = verificar_token()
    if payload is None:
        return jsonify(error="Token inválido o ausente"), 401
    return jsonify(usuario=payload["sub"], role=payload["role"])


@app.get("/admin")
def admin():
    payload = verificar_token()
    if payload is None:
        return jsonify(error="Token inválido o ausente"), 401
    if payload.get("role") != "admin":
        return jsonify(error="Solo administradores"), 403
    return jsonify(mensaje="Bienvenido al panel de administración",
                   flag="FLAG{jwt_roto_por_" + payload["sub"] + "}")


@app.post("/logout")
def logout():
    # El servidor no guarda estado: solo le pide al cliente que borre el token
    return jsonify(mensaje="Sesión cerrada. Borra tu token.")


if __name__ == "__main__":
    app.run(port=5000)"""""

import datetime
import os
import uuid

import jwt
from dotenv import load_dotenv
from flask import Flask, request, jsonify

load_dotenv()  # carga las variables del archivo .env

app = Flask(__name__)

# CORRECCIÓN 2: secreto largo, aleatorio y fuera del código
SECRET = os.environ.get("JWT_SECRET", "")
if len(SECRET) < 32:
    raise RuntimeError("JWT_SECRET no existe o es demasiado corto (mínimo 32 caracteres)")

ALGORITMO = "HS256"
DURACION = datetime.timedelta(minutes=15)

USUARIOS = {
    "alumno": {"password": "alumno123", "role": "user"},
    "admin": {"password": "Xk9#mP2$vL7qW4nZ", "role": "admin"},
}

# CORRECCIÓN 3b: lista de tokens revocados (en producción: Redis o BD)
REVOCADOS = set()


def verificar_token():
    """Devuelve los datos del usuario si el token es válido, o None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):]
    try:
        # CORRECCIÓN 1: el algoritmo lo fija el servidor, nunca el token
        payload = jwt.decode(
            token, SECRET, algorithms=[ALGORITMO],
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except jwt.PyJWTError:
        return None

    if payload["jti"] in REVOCADOS:
        return None

    # Mediación completa: el rol se consulta en la "BD" en cada request,
    # no se confía en lo que diga el token
    usuario = USUARIOS.get(payload["sub"])
    if usuario is None:
        return None
    return {"sub": payload["sub"], "role": usuario["role"], "jti": payload["jti"]}


@app.post("/login")
def login():
    datos = request.get_json(silent=True) or {}
    nombre = datos.get("usuario")
    usuario = USUARIOS.get(nombre)
    if not usuario or usuario["password"] != datos.get("password"):
        return jsonify(error="Credenciales inválidas"), 401
    ahora = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": nombre,
        "iat": ahora,
        "exp": ahora + DURACION,  # CORRECCIÓN 3a: el token caduca
        "jti": str(uuid.uuid4()),  # identificador único para poder revocarlo
    }
    token = jwt.encode(payload, SECRET, algorithm=ALGORITMO)
    return jsonify(token=token)


@app.get("/perfil")
def perfil():
    usuario = verificar_token()
    if usuario is None:
        return jsonify(error="Token inválido o ausente"), 401
    return jsonify(usuario=usuario["sub"], role=usuario["role"])


@app.get("/admin")
def admin():
    usuario = verificar_token()
    if usuario is None:
        return jsonify(error="Token inválido o ausente"), 401
    if usuario["role"] != "admin":
        return jsonify(error="Solo administradores"), 403
    return jsonify(mensaje="Bienvenido al panel de administración")


@app.post("/logout")
def logout():
    usuario = verificar_token()
    if usuario is None:
        return jsonify(error="Token inválido o ausente"), 401
    REVOCADOS.add(usuario["jti"])
    return jsonify(mensaje="Sesión cerrada. El token ya no es válido.")


if __name__ == "__main__":
    app.run(port=5000)