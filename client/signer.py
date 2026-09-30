"""Firma de peticiones: la usan el cliente, los ataques y los tests."""
import secrets
import time

from server.security import (build_message, compute_hmac,
                             HEADER_SIGNATURE, HEADER_NONCE, HEADER_TIMESTAMP)


# Prepara una petición firmada en el lado del cliente

def signed_headers(token: str, session_key_hex: str, method: str, path: str, body: bytes) -> dict:
    """Devuelve las cabeceras de una petición firmada con HMAC-SHA256."""
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)                      # 128 bits, nuevo en cada petición
    message = build_message(method, path, timestamp, nonce, body)
    signature = compute_hmac(bytes.fromhex(session_key_hex), message)
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        HEADER_SIGNATURE: signature,
        HEADER_NONCE: nonce,
        HEADER_TIMESTAMP: timestamp,
    }