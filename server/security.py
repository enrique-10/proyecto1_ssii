import hashlib
import hmac
import re
import sqlite3
import time

from server.db import get_connection, init_db

TIMESTAMP_WINDOW = 60                           # segundos de tolerancia (RS3)
NONCE_RE = re.compile(r"[0-9a-f]{32}")          # 16 bytes en hex (128 bits)
SIGNATURE_RE = re.compile(r"[0-9a-f]{64}")      # HMAC-SHA256 en hex (256 bits)

# Nombres de las cabeceras de seguridad (acuerdo cliente <-> servidor)
HEADER_SIGNATURE = "X-Signature"
HEADER_NONCE = "X-Nonce"
HEADER_TIMESTAMP = "X-Timestamp"


class SecurityError(Exception):
    def __init__(self, message, status_code=401):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---------- Construcción y cálculo de la firma ----------

# Lo que se va a firmar después de cualquier petición del cliente
def build_message(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    """Texto exacto que se firma. Cliente y servidor deben construirlo igual."""
    header = f"{method.upper()}|{path}|{timestamp}|{nonce}|".encode("utf-8")
    return header + body


def compute_hmac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


# ---------- Nonces ----------

def purge_old_nonces(conn, now: int):
    """Borra los nonces fuera de la ventana: esos mensajes ya se rechazan por timestamp."""
    conn.execute("DELETE FROM nonces WHERE timestamp < ?", (now - TIMESTAMP_WINDOW,))


def register_nonce(nonce: str, timestamp: int):
    now = int(time.time())
    conn = get_connection()
    try:
        purge_old_nonces(conn, now)
        conn.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)", (nonce, timestamp))
        conn.commit()
    except sqlite3.IntegrityError:
        raise SecurityError("Nonce repetido: posible ataque de replay")
    finally:
        conn.close()


# ---------- Verificación completa ----------

def verify_request(session_key_hex: str, method: str, path: str,
                   signature, nonce, timestamp, body: bytes):
    """Lanza SecurityError si la petición no es íntegra, auténtica y fresca."""

    # signature: para autenticidad e integridad -> MitM
    # nonce: unicidad (cada mensaje se acepta una sola vez) -> Replay
    # timestamp: frescura -> replay de mensajes antiguos

    # 1. Formato de las cabeceras (tramas corruptas o incompletas)
    if not signature or not nonce or not timestamp:
        raise SecurityError("Faltan cabeceras de seguridad", 400)
    if not SIGNATURE_RE.fullmatch(signature):
        raise SecurityError("Formato de firma inválido", 400)
    if not NONCE_RE.fullmatch(nonce):
        raise SecurityError("Formato de nonce inválido", 400)
    try:
        ts = int(timestamp)
    except ValueError:
        raise SecurityError("Formato de timestamp inválido", 400)

    # 2. Ventana de tiempo
    now = int(time.time())
    if abs(now - ts) > TIMESTAMP_WINDOW:
        raise SecurityError("Timestamp fuera de la ventana permitida")

    # 3. Integridad y autenticidad: HMAC comparado en tiempo constante (RS4)
    # con el compare_digest nos aseguramos que recorra la firma entera en vez de parar en el bucle que recorre comparandolo uino por uno
    # asi evitamos que cualquier atacante consiga sacar la firma por comporbaciones de tiempo de respuesta
    expected = compute_hmac(bytes.fromhex(session_key_hex),
                            build_message(method, path, timestamp, nonce, body))
    if not hmac.compare_digest(expected, signature):
        raise SecurityError("Fallo de integridad: la firma HMAC no coincide")

    # 4. Anti-replay: el nonce no puede haberse usado antes
    register_nonce(nonce, ts)
