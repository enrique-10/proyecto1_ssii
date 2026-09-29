# Cómo trabajar en este repo

## Primera vez
    git clone https://github.com/enrique-10/proyecto1_ssii.git
    cd proyecto1_ssii
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    python -m server.main        # comprobar que arranca

## Cada tarea
1. `git checkout main` y `git pull`
2. `git checkout -b nombre-de-tu-rama`
3. Commits pequeños y `git push`
4. Pull Request en GitHub → otro compañero lo revisa → Merge
5. `git checkout main` y `git pull`

## Reglas
- Nunca se trabaja directamente en `main`.
- Cada uno toca solo sus archivos. Para cambiar `server/` avisad antes.
- La firma HMAC NO se reimplementa: importad `build_message` y
  `compute_hmac` de `server/security.py`.
- Si instaláis una librería: `pip freeze > requirements.txt` y subidlo.
- Nada de `git push --force`.
- Anotad cómo usáis la IA (para el apartado de la memoria).

## Reparto
| Quién | Rama | Carpetas |
|---|---|---|
| Enrique | `cliente` | `client/` |
| Compañero 2 | `ataques` | `attacks/`, `tests/test_security.py`, `evidencias/` |
| Compañero 3 | `tests` | `tests/test_auth.py`, `tests/test_transfer.py`, `README.md` |