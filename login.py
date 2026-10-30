import requests

URL = "http://127.0.0.1:5000"

# Aquí se hace el login enviando usuario y contraseña
r = requests.post(f"{URL}/login", json={"usuario": "alumno", "password": "alumno123"})
token = r.json()["token"]
print("Token obtenido:\n", token)

# Aquí se crea automáticamente el archivo token.txt y guarda el token adentro
with open("token.txt", "w") as f:
    f.write(token)
print("\nGuardado en token.txt")

# Prueba entrar a las dos rutas protegidas
r = requests.get(f"{URL}/perfil", headers={"Authorization": f"Bearer {token}"})
print("\n/perfil ->", r.status_code, r.json())

r = requests.get(f"{URL}/admin", headers={"Authorization": f"Bearer {token}"})
print("/admin  ->", r.status_code, r.json())
