import sqlite3
from pathlib import Path

# La base de datos se crea en la raíz del proyecto
DB_PATH = Path(__file__).resolve().parent.parent / "secbank.db"

# el metodo de hashing que usaremos ("argon2-cffi"), ya mete de por si el SALT, es por eso
# por lo que no hay campo de SALT en la tabla users
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token        TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    session_key  TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT    PRIMARY KEY,
    timestamp  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    tx_id               TEXT    PRIMARY KEY,
    user_id             INTEGER NOT NULL,
    origin_account      TEXT    NOT NULL,
    destination_account TEXT    NOT NULL,
    amount              REAL    NOT NULL,
    currency            TEXT    NOT NULL,
    timestamp           INTEGER NOT NULL,
    nonce               TEXT    NOT NULL,
    hmac                TEXT    NOT NULL,
    received_at         INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # filas accesibles por nombre: fila["username"]
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    conn = get_connection()
    tablas = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    print("Tablas creadas:", [t["name"] for t in tablas])
    conn.close()