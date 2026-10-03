import unittest
import time
import secrets
import json
from server.db import init_db
from server.security import verify_request, SecurityError, compute_hmac, build_message

class TestSecurityModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        
    def setUp(self):
        self.session_key = secrets.token_bytes(32).hex()
        self.path = "/api/v1/transfer"
        self.body = json.dumps({"amount": 200.0, "destination_account": "ES98"}).encode()
        
    def firmar(self, body: bytes, ts=None, nonce=None):
        ts = ts or str(int(time.time()))
        nonce = nonce or secrets.token_hex(16)
        msg = build_message("POST", self.path, ts, nonce, body)
        sig = compute_hmac(bytes.fromhex(self.session_key), msg)
        return sig, nonce, ts

    def test_1_peticion_legitima(self):
        sig, nonce, ts = self.firmar(self.body)
        try:
            verify_request(self.session_key, "POST", self.path, sig, nonce, ts, self.body)
            print("\n1. Legítima: ACEPTADA")
        except SecurityError as e:
            self.fail(f"Petición legítima rechazada inesperadamente: {e.message}")

    def test_2_ataque_replay(self):
        sig, nonce, ts = self.firmar(self.body)
        # 1er envío (legítimo)
        verify_request(self.session_key, "POST", self.path, sig, nonce, ts, self.body)
        
        # 2do envío (replay exacto)
        with self.assertRaises(SecurityError) as context:
            verify_request(self.session_key, "POST", self.path, sig, nonce, ts, self.body)
        print(f"2. Replay (mismo mensaje otra vez): RECHAZADA ({context.exception.status_code}) -> {context.exception.message}")

    def test_3_ataque_mitm(self):
        sig, nonce, ts = self.firmar(self.body)
        alterado = self.body.replace(b"200.0", b"2000.0")
        
        with self.assertRaises(SecurityError) as context:
            verify_request(self.session_key, "POST", self.path, sig, nonce, ts, alterado)
        print(f"3. MitM (importe alterado): RECHAZADA ({context.exception.status_code}) -> {context.exception.message}")

    def test_4_tiempo_caducado(self):
        ts_antiguo = str(int(time.time()) - 3600)
        sig, nonce, ts = self.firmar(self.body, ts=ts_antiguo)
        
        with self.assertRaises(SecurityError) as context:
            verify_request(self.session_key, "POST", self.path, sig, nonce, ts, self.body)
        print(f"4. Timestamp de hace 1 hora: RECHAZADA ({context.exception.status_code}) -> {context.exception.message}")

    def test_5_firma_corrupta(self):
        _, nonce, ts = self.firmar(self.body)
        
        with self.assertRaises(SecurityError) as context:
            verify_request(self.session_key, "POST", self.path, "zzz", nonce, ts, self.body)
        print(f"5. Firma corrupta: RECHAZADA ({context.exception.status_code}) -> {context.exception.message}")

    def test_6_sin_cabeceras(self):
        with self.assertRaises(SecurityError) as context:
            verify_request(self.session_key, "POST", self.path, None, None, None, self.body)
        print(f"6. Sin cabeceras: RECHAZADA ({context.exception.status_code}) -> {context.exception.message}")

if __name__ == '__main__':
    unittest.main()