"""Cliente de SecBank: menú por consola y clase ApiClient reutilizable."""
import argparse
import getpass
import json
import uuid

import requests

from client.signer import signed_headers

DEFAULT_URL = "http://127.0.0.1:8080"


class ApiClient:
    """Habla con el servidor. La usan el menú, los ataques y los tests."""

    def __init__(self, base_url: str = DEFAULT_URL):
        self.base_url = base_url.rstrip("/")
        self.username = None
        self.token = None
        self.session_key = None

    @property
    def logged_in(self) -> bool:
        return self.token is not None

    # ---------- Sin firma (todavía no hay session_key) ----------

    def register(self, username: str, password: str) -> requests.Response:
        return requests.post(f"{self.base_url}/api/v1/register",
                             json={"username": username, "password": password}, timeout=10)

    def login(self, username: str, password: str) -> requests.Response:
        r = requests.post(f"{self.base_url}/api/v1/login",
                          json={"username": username, "password": password}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            self.username = username
            self.token = data["token"]
            self.session_key = data["session_key"]
        return r

    # ---------- Con firma HMAC ----------

    def _signed_post(self, path: str, body: bytes) -> requests.Response:
        headers = signed_headers(self.token, self.session_key, "POST", path, body)
        return requests.post(f"{self.base_url}{path}", data=body, headers=headers, timeout=10)

    def transfer(self, origin: str, destination: str, amount: float) -> requests.Response:
        tx = {
            "tx_id": str(uuid.uuid4()),
            "origin_account": origin,
            "destination_account": destination,
            "amount": amount,
            "currency": "EUR",
        }
        body = json.dumps(tx).encode("utf-8")
        return self._signed_post("/api/v1/transfer", body)

    def logout(self) -> requests.Response:
        r = self._signed_post("/api/v1/logout", b"")
        if r.status_code == 200:
            self.username = self.token = self.session_key = None
        return r


# ---------- Menú por consola ----------

def show(r: requests.Response):
    try:
        detail = r.json().get("detail", r.json())
    except ValueError:
        detail = r.text
    ok = "✔" if r.status_code < 400 else "✘"
    print(f"  {ok} [{r.status_code}] {detail}")


def menu(api: ApiClient):
    while True:
        who = f"sesión: {api.username}" if api.logged_in else "sin sesión"
        print(f"\n=== SecBank ({who}) ===")
        print("1. Registrarse\n2. Iniciar sesión\n3. Transferencia\n4. Cerrar sesión\n0. Salir")
        option = input("> ").strip()

        try:
            if option == "1":
                user = input("  Usuario: ").strip()
                show(api.register(user, getpass.getpass("  Contraseña: ")))

            elif option == "2":
                user = input("  Usuario: ").strip()
                r = api.login(user, getpass.getpass("  Contraseña: "))
                if r.status_code == 200:
                    print(f"  ✔ [200] Sesión iniciada como {user}")   # no se muestran token ni clave
                else:
                    show(r)

            elif option == "3":
                if not api.logged_in:
                    print("  Primero inicia sesión.")
                    continue
                origin = input("  Cuenta origen (IBAN): ").strip().upper()
                destination = input("  Cuenta destino (IBAN): ").strip().upper()
                try:
                    amount = float(input("  Importe (EUR): ").replace(",", "."))
                except ValueError:
                    print("  Importe no válido.")
                    continue
                show(api.transfer(origin, destination, amount))

            elif option == "4":
                if not api.logged_in:
                    print("  No hay ninguna sesión abierta.")
                    continue
                show(api.logout())

            elif option == "0":
                break
            else:
                print("  Opción no válida.")

        except requests.ConnectionError:
            print(f"  ✘ No se pudo conectar con {api.base_url}. ¿Está arrancado el servidor?")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cliente de SecBank")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="URL del servidor (por defecto %(default)s; usa :8081 para pasar por el proxy MitM)")
    menu(ApiClient(parser.parse_args().url))