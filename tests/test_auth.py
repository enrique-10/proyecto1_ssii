import unittest
import uuid
from server.db import init_db, get_connection
from server.auth import register_user, login, logout, get_session, AuthError

class TestAuthModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        
    def setUp(self):
        #Generamos un nombre de usuario único para cada test usando uuid, para evitar que el usuario ya exista
        self.username = f"test_{uuid.uuid4().hex[:6]}"
        self.password = "PasswordSegura123!"

    def test_1_registro_exitoso(self):
        #Probamos que el usuario se crea correctamente
        register_user(self.username, self.password)
        
        #Comprobamos en la base de datos
        conn = get_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (self.username,)).fetchone()
        conn.close()
        
        self.assertIsNotNone(user, "El usuario debería existir en la base de datos")
        self.assertEqual(user["username"], self.username)

    def test_2_registro_datos_invalidos(self):
        #Nombre de usuario demasiado corto (debe tener entre 3 y 32 caracteres)
        with self.assertRaises(AuthError) as context:
            register_user("ab", self.password)
        self.assertIn("Nombre de usuario inválido", context.exception.message)

        #Contraseña demasiado corta (la regla dice mínimo 8)
        with self.assertRaises(AuthError) as context:
            register_user(self.username, "1234567")
        self.assertIn("La contraseña debe tener al menos", context.exception.message)

    def test_3_login_exitoso_y_logout(self):
        #Registramos al usuario
        register_user(self.username, self.password)
        
        #Hacemos login y verificamos que devuelve token y session_key
        session = login(self.username, self.password)
        self.assertIn("token", session)
        self.assertIn("session_key", session)
        
        #Comprobamos que la sesión existe en la base de datos
        db_session = get_session(session["token"])
        self.assertIsNotNone(db_session, "La sesión debería estar activa")
        
        #Hacemos logout y comprobamos que se borra
        logout(session["token"])
        self.assertIsNone(get_session(session["token"]), "La sesión debería haber sido borrada")

    def test_4_login_bloqueo_por_intentos(self):
        register_user(self.username, self.password)
        
        #Hacemos 5 intentos fallidos
        for i in range(5):
            with self.assertRaises(AuthError) as context:
                login(self.username, "ClaveIncorrecta!")
            self.assertEqual(context.exception.status_code, 401)
            
        #El 6º intento debe lanzar error de cuenta bloqueada
        with self.assertRaises(AuthError) as context:
            login(self.username, "ClaveIncorrecta!")
        self.assertEqual(context.exception.status_code, 429)
        self.assertIn("Cuenta bloqueada temporalmente", context.exception.message)

if __name__ == '__main__':
    unittest.main()


#Desde la terminal, si queremos borrar los usuarios de la base de datos creados en este test, se puede usar:   (elimina los que empiezan con test)
#python -c "from server.db import get_connection; conn=get_connection(); conn.execute('''DELETE FROM users WHERE username LIKE 'test_%' '''); conn.commit(); conn.close(); print('Usuarios de test eliminados')"      