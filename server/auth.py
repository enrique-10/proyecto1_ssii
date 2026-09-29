import re
import secrets
import sqlite3
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from server.db import get_connection, init_db

# Argon2id con los parámetros por defecto de argon2-cffi:
# 3 iteraciones, 64 MiB de memoria, 4 hilos, sal aleatoria de 16 bytes
ph = PasswordHasher()

MAX_ATTEMPTS = 5          # intentos fallidos antes de bloquear
LOCK_SECONDS = 300        # duración del bloqueo (5 min)
SESSION_TTL = 1800        # duración de la sesión (30 min)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$") # un caracter que sea letra mayuscula, minuscula, digito o guion bajo, entre 3 y 32 caracteres
MIN_PASSWORD_LEN = 8

# Hash de una contraseña aleatoria que no pertenece a nadie. Se usa cuando el
# usuario no existe, para que el login tarde lo mismo (evita enumerar usuarios por tiempo).
# Con esto evitamos el ataque de la diapositiva 9 "Lateral Channel" de comprobaciones de tiempo, pero no para contraseñas,
# si no para usuarios existentes o no existentes (el atacante no sabrá si el usuario existe o no porque tarda lo mismo en devolver el token en un caso u otro)
DUMMY_HASH = ph.hash(secrets.token_hex(16))

SEED_USERS = [
    ("alice", "AlicePass123!"),
    ("bob", "BobPass123!"),
    ("carol", "CarolPass123!"),
]


class AuthError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---------- Contraseñas ----------

def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# ---------- Registro ----------

def register_user(username: str, password: str):
    if not USERNAME_RE.fullmatch(username or ""):
        raise AuthError("Nombre de usuario inválido (3-32 caracteres: letras, números o _)")
    if len(password or "") < MIN_PASSWORD_LEN:
        raise AuthError(f"La contraseña debe tener al menos {MIN_PASSWORD_LEN} caracteres")

    password_hash = hash_password(password)
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, int(time.time())),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise AuthError("El usuario ya existe", status_code=409)
    finally:
        conn.close()


# ---------- Login ----------

def login(username: str, password: str) -> dict:
    now = int(time.time())
    conn = get_connection()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # En el caso de que el usuario no exista, verificamos la contraseña con un hash aleatorio cualquira para que un supuesto atacante no pueda saber si el usuario existe o no según el tiempo de resputesta
        if user is None:
            verify_password(DUMMY_HASH, password)   # mismo coste que con un usuario real
            raise AuthError("Credenciales inválidas", 401)

        if user["locked_until"] > now:
            raise AuthError("Cuenta bloqueada temporalmente. Inténtalo más tarde", 429)

        if not verify_password(user["password_hash"], password):
            attempts = user["failed_attempts"] + 1
            if attempts >= MAX_ATTEMPTS:
                conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                    (now + LOCK_SECONDS, user["id"]),
                )
            else:
                conn.execute(
                    "UPDATE users SET failed_attempts = ? WHERE id = ?",
                    (attempts, user["id"]),
                )
            conn.commit()
            raise AuthError("Credenciales inválidas", 401)

        # Login correcto: se reinicia el contador y se crea la sesión
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
            (user["id"],),
        )
        token = secrets.token_urlsafe(32)
        session_key = secrets.token_bytes(32).hex()      # 256 bits (RS2b)
        conn.execute(
            "INSERT INTO sessions (token, user_id, session_key, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (token, user["id"], session_key, now, now + SESSION_TTL),
        )
        conn.commit()
        return {"token": token, "session_key": session_key, "expires_at": now + SESSION_TTL}
    finally:
        conn.close()


# ---------- Sesiones ----------

def get_session(token: str):
    """Devuelve la sesión si existe y no ha caducado; si no, None."""
    now = int(time.time())
    conn = get_connection()
    try:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.commit()
        return conn.execute(
            "SELECT * FROM sessions WHERE token = ?", (token,)
        ).fetchone()
    finally:
        conn.close()


def logout(token: str):
    conn = get_connection()
    try:
        cur = conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        if cur.rowcount == 0:
            raise AuthError("Sesión no válida", 401)
    finally:
        conn.close()


# ---------- Usuarios precargados ----------

def seed_users():
    for username, password in SEED_USERS:
        try:
            register_user(username, password)
        except AuthError:
            pass   # ya existía


# ---------- Prueba rápida ----------

if __name__ == "__main__":
    init_db()   # podemos correrlo siempre que queramos gracias a los IF NOT EXISTS
    seed_users()
    s = login("alice", "AlicePass123!")
    print("Login alice OK, token:", s["token"][:12], "...")

    try:
        register_user("alice", "OtraPass123!")
    except AuthError as e:
        print("Registro duplicado:", e.message)

    for i in range(6):
        try:
            login("bob", "incorrecta")
        except AuthError as e:
            print(f"Intento {i + 1} bob:", e.message)

    logout(s["token"])
    print("Tras logout, sesión de alice:", get_session(s["token"]))