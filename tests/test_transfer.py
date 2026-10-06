import json
import secrets
import time
import unittest
import uuid
from fastapi.testclient import TestClient

from server.auth import register_user, login
from server.db import get_connection, init_db
from server.main import app
from server.security import build_message, compute_hmac

class TestTransferModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        #TestClient permite simular peticiones a la API sin arrancar el servidor
        cls.client = TestClient(app)

    def setUp(self):
        #Generamos un usuario para los tests
        self.username = f"usr_{uuid.uuid4().hex[:6]}"
        self.password = "ClaveSegura123!"
        register_user(self.username, self.password)
        
        #Hacemos login y guardamos la sesión para usar el token y la key
        self.session = login(self.username, self.password)
        self.path = "/api/v1/transfer"

    def tearDown(self):
        #Limpieza de la base de datos para no dejar rastro de los tests
        conn = get_connection()
        try:
            conn.execute("DELETE FROM transactions WHERE user_id IN (SELECT id FROM users WHERE username = ?)", (self.username,))
            conn.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username = ?)", (self.username,))
            conn.execute("DELETE FROM users WHERE username = ?", (self.username,))
            conn.commit()
        finally:
            conn.close()

    def _firmar_peticion(self, body_bytes: bytes) -> dict:
        """Helper que genera las cabeceras requeridas usando los métodos oficiales de seguridad."""
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        
        msg = build_message("POST", self.path, timestamp, nonce, body_bytes)
        firma = compute_hmac(bytes.fromhex(self.session["session_key"]), msg)
        
        return {
            "Authorization": f"Bearer {self.session['token']}",
            "Content-Type": "application/json",
            "X-Signature": firma,
            "X-Nonce": nonce,
            "X-Timestamp": timestamp
        }

    def test_1_transferencia_correcta(self):
        #Generamos una transacción válida que cumple con el esquema TransferRequest
        tx_id = str(uuid.uuid4())
        tx_data = {
            "tx_id": tx_id,
            "origin_account": "ES1234567890123456789012",
            "destination_account": "ES9876543210987654321098",
            "amount": 150.50,
            "currency": "EUR"
        }
        body = json.dumps(tx_data).encode("utf-8")
        headers = self._firmar_peticion(body)
        
        #Simulamos la petición POST
        res = self.client.post(self.path, content=body, headers=headers)
        
        #Comprobamos que el servidor la acepta
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["detail"], "Transferencia realizada")
        
        #Comprobamos que se guardó en la base de datos
        conn = get_connection()
        tx_db = conn.execute("SELECT * FROM transactions WHERE tx_id = ?", (tx_id,)).fetchone()
        conn.close()
        self.assertIsNotNone(tx_db)
        self.assertEqual(tx_db["amount"], 150.50)

    def test_2_importe_negativo_invalido(self):
        tx_data = {
            "tx_id": str(uuid.uuid4()),
            "origin_account": "ES1234567890123456789012",
            "destination_account": "ES9876543210987654321098",
            "amount": -50.0,
            "currency": "EUR"
        }
        body = json.dumps(tx_data).encode("utf-8")
        headers = self._firmar_peticion(body)
        
        res = self.client.post(self.path, content=body, headers=headers)
        
        self.assertEqual(res.status_code, 400)
        #Cambiamos "Petición mal formada" por "Datos de transferencia inválidos"
        self.assertEqual(res.json()["detail"], "Datos de transferencia inválidos")

    def test_3_mitm_modificacion_en_transito(self):
        #Transacción original
        tx_data = {
            "tx_id": str(uuid.uuid4()),
            "origin_account": "ES1234567890123456789012",
            "destination_account": "ES9876543210987654321098",
            "amount": 100.0,
            "currency": "EUR"
        }
        body_original = json.dumps(tx_data).encode("utf-8")
        
        #El cliente legítimo firma la petición por 100 EUR
        headers = self._firmar_peticion(body_original)
        
        #ATAQUE: El atacante captura la petición y cambia el importe a 9999 EUR
        tx_data["amount"] = 9999.0
        body_alterado = json.dumps(tx_data).encode("utf-8")
        
        #El atacante envía el body alterado manteniendo las cabeceras originales
        res = self.client.post(self.path, content=body_alterado, headers=headers)
        
        #El servidor debe detectar que la firma no coincide con el nuevo body
        self.assertEqual(res.status_code, 401)
        self.assertIn("Fallo de integridad", res.json()["detail"])

if __name__ == '__main__':
    unittest.main()