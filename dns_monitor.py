"""
============================================================
Sistema IDS Institucional
Módulo: dns_monitor.py
Descripción: Monitorea y registra los dominios consultados en la red
             interceptando paquetes DNS (puerto 53 UDP).
             Guarda la bitácora en SQLite (logs.db) para análisis
             posterior y genera un log en texto plano.
============================================================
"""

import sqlite3
import logging
from datetime import datetime

import config

logger = logging.getLogger("IDS.DNS")


# ── Inicialización de base de datos ──────────────────────────────────────────

def inicializar_db() -> None:
    """
    Crea la tabla de registros DNS si no existe.
    Se llama una sola vez al iniciar el sistema.
    """
    try:
        conn = sqlite3.connect(config.DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dns_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                ip_origen   TEXT    NOT NULL,
                mac_origen  TEXT    NOT NULL,
                dominio     TEXT    NOT NULL,
                tipo_query  TEXT    DEFAULT 'A',
                autorizado  INTEGER DEFAULT 1
            )
        """)
        conn.commit()
        conn.close()
        logger.info(f"Base de datos inicializada en: {config.DB_FILE}")
    except sqlite3.Error as e:
        logger.error(f"Error al inicializar base de datos: {e}")


# ── Registro de consultas DNS ─────────────────────────────────────────────────

def registrar_consulta(ip_origen: str, mac_origen: str,
                        dominio: str, tipo_query: str = "A",
                        autorizado: bool = True) -> None:
    """
    Guarda una consulta DNS en la base de datos y en el archivo de alertas.
    
    Parámetros:
        ip_origen   : IP del equipo que hizo la consulta
        mac_origen  : MAC del equipo que hizo la consulta
        dominio     : Nombre de dominio consultado (ej. google.com)
        tipo_query  : Tipo de registro DNS (A, AAAA, MX, etc.)
        autorizado  : Si el dispositivo origen estaba en la whitelist
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    estado    = "AUTORIZADO" if autorizado else "NO_AUTORIZADO"

    # Guardar en SQLite
    try:
        conn = sqlite3.connect(config.DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO dns_log (timestamp, ip_origen, mac_origen, dominio, tipo_query, autorizado)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, ip_origen, mac_origen, dominio, tipo_query, int(autorizado)))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Error al guardar en DB: {e}")

    # Guardar en log de texto plano (para el manual de usuario)
    linea_log = (
        f"[{timestamp}] DNS | Estado: {estado} | "
        f"IP: {ip_origen} | MAC: {mac_origen} | "
        f"Dominio: {dominio} | Tipo: {tipo_query}\n"
    )
    try:
        with open(config.ALERTS_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(linea_log)
    except IOError as e:
        logger.error(f"Error al escribir log de alertas: {e}")

    logger.info(f"[DNS] {estado} | {ip_origen} → {dominio} ({tipo_query})")


# ── Consultas de reportes ────────────────────────────────────────────────────

def obtener_reporte(limit: int = 50) -> list[dict]:
    """
    Retorna los últimos registros DNS de la base de datos.
    Útil para generar reportes en pantalla o en interfaz.
    """
    try:
        conn   = sqlite3.connect(config.DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT timestamp, ip_origen, mac_origen, dominio, tipo_query, autorizado
            FROM dns_log
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        filas = cursor.fetchall()
        conn.close()

        return [
            {
                "timestamp":  f[0],
                "ip_origen":  f[1],
                "mac_origen": f[2],
                "dominio":    f[3],
                "tipo_query": f[4],
                "autorizado": bool(f[5])
            }
            for f in filas
        ]
    except sqlite3.Error as e:
        logger.error(f"Error al consultar reporte: {e}")
        return []


def obtener_estadisticas() -> dict:
    """
    Retorna estadísticas básicas: total consultas, dominios únicos,
    consultas no autorizadas.
    """
    try:
        conn   = sqlite3.connect(config.DB_FILE)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM dns_log")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT dominio) FROM dns_log")
        dominios_unicos = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM dns_log WHERE autorizado = 0")
        no_autorizados = cursor.fetchone()[0]

        conn.close()
        return {
            "total_consultas":   total,
            "dominios_unicos":   dominios_unicos,
            "no_autorizados":    no_autorizados
        }
    except sqlite3.Error as e:
        logger.error(f"Error al obtener estadísticas: {e}")
        return {}
