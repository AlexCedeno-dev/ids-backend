"""
============================================================
Sistema IDS Institucional
Módulo: config.py
Descripción: Carga y valida la configuración desde el archivo .env.
             Centraliza el acceso a todas las variables de entorno
             para que ningún otro módulo tenga credenciales hardcoded.
============================================================
"""

import os
import sys
from dotenv import load_dotenv

# Cargar variables del archivo .env
load_dotenv()


def _require(var_name: str) -> str:
    """
    Obtiene una variable de entorno obligatoria.
    Si no existe, termina el programa con un mensaje claro.
    """
    value = os.getenv(var_name)
    if not value:
        print(f"[ERROR] La variable de entorno '{var_name}' no está definida.")
        print("        Copia '.env.example' como '.env' y completa tus datos.")
        sys.exit(1)
    return value


# ── SMTP ────────────────────────────────────────────────────
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = _require("SMTP_USER")
SMTP_PASSWORD = _require("SMTP_PASSWORD")

# ── Administrador ────────────────────────────────────────────
ADMIN_EMAIL   = _require("ADMIN_EMAIL")

# ── Organización ─────────────────────────────────────────────
ORG_NAME      = os.getenv("ORG_NAME", "Organización")

# ── Red ──────────────────────────────────────────────────────
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")

# ── APIs externas ────────────────────────────────────────────
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# ── Rutas de archivos del proyecto ───────────────────────────
BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE   = os.path.join(BASE_DIR, "data", "whitelist.json")
BLACKLIST_FILE   = os.path.join(BASE_DIR, "data", "blacklist_ips.json")
DB_FILE          = os.path.join(BASE_DIR, "data", "logs.db")
ALERTS_LOG_FILE  = os.path.join(BASE_DIR, "reports", "alertas.log")

# ── Nivel de log ──────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
