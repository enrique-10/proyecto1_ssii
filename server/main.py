import json
import logging
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from server import auth
from server.db import get_connection, init_db
from server.security import SecurityError, verify_request

# ---------- Logs: consola + evidencias/server.log ----------

LOG_FILE = Path(__file__).resolve().parent.parent / "evidencias" / "server.log"
LOG_FILE.parent.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(LOG_FILE, encoding="utf-8")],
)
log = logging.getLogger("secbank")
logging.getLogger("httpx").setLevel(logging.WARNING)

# ---------- Arranque ----------


# Ponemos esto para que se pueda hacer de manera interna con la librería "Starlette" que es sobre la que está contstruida FastAPI
# un "
"""
async with lifestpan(app):          # <- ENTRA: ejecuta código de lifespan hasta el "yield
    atender_peticiones()            # <- Todo el tiempo que el servidor está encendido
                                    # <- SALE (Ctrl + C): ejecuta lo que haya tras el yield. En

"""
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    auth.seed_users()
    log.info("Servidor SecBank iniciado (usuarios precargados: alice, bob, carol)")
    yield


app = FastAPI(title="SecBank", lifespan=lifespan)


# ---------- Modelos de datos (validación de lo que llega) ----------

class Credentials(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


IBAN = r"^[A-Z]{2}[0-9]{22}$"


class TransferRequest(BaseModel):
    tx_id: UUID
    origin_account: str = Field(pattern=IBAN)
    destination_account: str = Field(pattern=IBAN)
    amount: float = Field(gt=0, le=1_000_000)
    currency: Literal["EUR"]


# ---------- Manejo de errores: nunca se cae, siempre responde JSON ----------

@app.exception_handler(auth.AuthError)
async def auth_error_handler(request: Request, exc: auth.AuthError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(SecurityError)
async def security_error_handler(request: Request, exc: SecurityError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    log.warning("RECHAZADA %s %s: petición mal formada", request.method, request.url.path)
    return JSONResponse(status_code=400, content={"detail": "Petición mal formada"})


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    log.exception("Error inesperado en %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Error interno del servidor"})


# ---------- Utilidades ----------

def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def require_session(request: Request):
    """Devuelve la sesión asociada al token Bearer, o lanza 401."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise auth.AuthError("Falta el token de sesión", 401)
    session = auth.get_session(header.removeprefix("Bearer ").strip())
    if session is None:
        raise auth.AuthError("Sesión no válida o caducada", 401)
    return session


async def verify_signed_request(request: Request, session) -> tuple[bytes, dict]:
    """Verifica HMAC, timestamp y nonce. Devuelve el body y las cabeceras de seguridad."""
    body = await request.body()
    sec = {
        "signature": request.headers.get("X-Signature"),
        "nonce": request.headers.get("X-Nonce"),
        "timestamp": request.headers.get("X-Timestamp"),
    }
    try:
        verify_request(session["session_key"], request.method, request.url.path,
                       sec["signature"], sec["nonce"], sec["timestamp"], body)
    except SecurityError as e:
        log.warning("RECHAZADA %s %s desde %s (user_id=%s): %s",
                    request.method, request.url.path, client_ip(request), session["user_id"], e.message)
        raise
    return body, sec


# ---------- Endpoints ----------

@app.post("/api/v1/register", status_code=201)
async def register(creds: Credentials, request: Request):
    try:
        auth.register_user(creds.username, creds.password)
    except auth.AuthError as e:
        log.warning("Registro rechazado de '%s' desde %s: %s", creds.username, client_ip(request), e.message)
        raise
    log.info("Usuario registrado: '%s'", creds.username)
    return {"detail": "Usuario registrado correctamente"}


@app.post("/api/v1/login")
async def login(creds: Credentials, request: Request):
    try:
        session = auth.login(creds.username, creds.password)
    except auth.AuthError as e:
        log.warning("Login fallido de '%s' desde %s: %s", creds.username, client_ip(request), e.message)
        raise
    log.info("Login correcto: '%s' desde %s", creds.username, client_ip(request))
    return session


@app.post("/api/v1/logout")
async def logout(request: Request):
    session = require_session(request)
    await verify_signed_request(request, session)     # el logout también va firmado
    auth.logout(session["token"])
    log.info("Logout: user_id=%s", session["user_id"])
    return {"detail": "Sesión cerrada"}


@app.post("/api/v1/transfer", status_code=201)
async def transfer(request: Request):
    session = require_session(request)

    # 1. Seguridad primero: HMAC + timestamp + nonce sobre los bytes exactos recibidos
    body, sec = await verify_signed_request(request, session)

    # 2. Solo si la firma es válida, se interpreta el contenido
    try:
        tx = TransferRequest.model_validate(json.loads(body))
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError):
        log.warning("RECHAZADA transferencia de user_id=%s: body mal formado", session["user_id"])
        return JSONResponse(status_code=400, content={"detail": "Datos de transferencia inválidos"})

    # 3. Guardar la transacción junto con su nonce y HMAC (registro auditable)
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO transactions (tx_id, user_id, origin_account, destination_account, amount, "
            "currency, timestamp, nonce, hmac, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(tx.tx_id), session["user_id"], tx.origin_account, tx.destination_account, tx.amount,
             tx.currency, int(sec["timestamp"]), sec["nonce"], sec["signature"], int(time.time())),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        log.warning("RECHAZADA transferencia %s: tx_id duplicado", tx.tx_id)
        return JSONResponse(status_code=409, content={"detail": "Transacción duplicada"})
    finally:
        conn.close()

    log.info("ACEPTADA transferencia %s: %.2f %s de %s a %s (user_id=%s)",
             tx.tx_id, tx.amount, tx.currency, tx.origin_account, tx.destination_account, session["user_id"])
    return {"detail": "Transferencia realizada", "tx_id": str(tx.tx_id)}


# ---------- Arranque directo: python -m server.main ----------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host="127.0.0.1", port=8080)