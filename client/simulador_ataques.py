import requests
import time
import uuid
import hmac
import hashlib
import json

BASE_URL = "http://127.0.0.1:8080/api/v1"

def build_message(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    header = f"{method.upper()}|{path}|{timestamp}|{nonce}|".encode("utf-8")
    return header + body

def main():
    print("=== INICIANDO SIMULACIÓN DE ATAQUES ===")
    
    print("\n[*] Obteniendo sesión de usuario legítimo (Alice)...")
    res_login = requests.post(f"{BASE_URL}/login", json={"username": "alice", "password": "AlicePass123!"})
    session_data = res_login.json()
    token = session_data["token"]
    session_key = session_data["session_key"]
    headers_auth = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # ==========================================
    # FLUJO 1: TRANSFERENCIA LEGÍTIMA
    # ==========================================
    print("\n[FLUJO LEGÍTIMO] Enviando transferencia de 100 EUR...")
    tx_legitima = {
        "tx_id": str(uuid.uuid4()),
        "origin_account": "ES1234567890123456789012",
        "destination_account": "ES9876543210987654321098",
        "amount": 100.0,
        "currency": "EUR"
    }
    body_legitimo = json.dumps(tx_legitima).encode("utf-8")
    nonce = uuid.uuid4().hex
    timestamp = str(int(time.time()))
    
    msg = build_message("POST", "/api/v1/transfer", timestamp, nonce, body_legitimo)
    firma = hmac.new(bytes.fromhex(session_key), msg, hashlib.sha256).hexdigest()
    
    headers_legitimos = {**headers_auth, "X-Signature": firma, "X-Nonce": nonce, "X-Timestamp": timestamp}
    
    # Enviamos
    res1 = requests.post(f"{BASE_URL}/transfer", data=body_legitimo, headers=headers_legitimos)
    print(f" -> Resultado Servidor: {res1.status_code} - {res1.json()}")

    # ==========================================
    # FLUJO 2: ATAQUE DE REPETICIÓN (REPLAY)
    # ==========================================
    print("\n[ATAQUE REPLAY] El atacante capturó el paquete anterior y lo reenvía EXACTAMENTE igual...")
    res2 = requests.post(f"{BASE_URL}/transfer", data=body_legitimo, headers=headers_legitimos)
    print(f" -> Resultado Servidor: {res2.status_code} - {res2.json()}")

    # ==========================================
    # FLUJO 3: ATAQUE MAN-IN-THE-MIDDLE (MitM)
    # ==========================================
    print("\n[ATAQUE MitM] El atacante intercepta un envío y cambia el importe a 9999 EUR en tránsito...")
    tx_mitm = tx_legitima.copy()
    tx_mitm["tx_id"] = str(uuid.uuid4())
    tx_mitm["amount"] = 9999.0
    
    body_alterado = json.dumps(tx_mitm).encode("utf-8")
    nonce_mitm = uuid.uuid4().hex
    timestamp_mitm = str(int(time.time()))
    
    tx_original_mitm = tx_mitm.copy()
    tx_original_mitm["amount"] = 100.0
    msg_original = build_message("POST", "/api/v1/transfer", timestamp_mitm, nonce_mitm, json.dumps(tx_original_mitm).encode("utf-8"))
    firma_robada = hmac.new(bytes.fromhex(session_key), msg_original, hashlib.sha256).hexdigest()
    
    headers_mitm = {**headers_auth, "X-Signature": firma_robada, "X-Nonce": nonce_mitm, "X-Timestamp": timestamp_mitm}
    
    res3 = requests.post(f"{BASE_URL}/transfer", data=body_alterado, headers=headers_mitm)
    print(f" -> Resultado Servidor: {res3.status_code} - {res3.json()}")

if __name__ == "__main__":
    main()