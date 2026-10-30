import requests

URL = "http://127.0.0.1:5000"

# Inicio de sesión normal
r = requests.post(f"{URL}/login", json={"usuario": "alumno", "password": "alumno123"})
token = r.json()["token"]
cabecera = {"Authorization": f"Bearer {token}"}

print("1. Antes del logout ->", requests.get(f"{URL}/perfil", headers=cabecera).status_code)

r = requests.post(f"{URL}/logout", headers=cabecera)
print("2. Logout           ->", r.json())

# Un atacante que copió el token antes del logout lo sigue usando
print("3. Después del logout ->", requests.get(f"{URL}/perfil", headers=cabecera).status_code)
print("\nSi ves 200 en el paso 3, el token sigue vivo aunque el usuario cerró sesión.")
