"""
============================================================
Sistema IDS Institucional
Módulo: dashboard.py
Descripción: Dashboard web con Flask para visualización en tiempo real
             de eventos de red capturados por el IDS.
             Lee datos directamente desde SQLite y los archivos de
             configuración existentes sin modificar ningún otro módulo.
============================================================
"""

import json
import os
import re
import sqlite3
from datetime import datetime

from flask import Flask, jsonify, render_template

# Rutas absolutas para que el dashboard funcione independientemente
# del directorio de trabajo desde el que se lance
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DB_FILE        = os.path.join(BASE_DIR, "data",    "logs.db")
ALERTS_LOG     = os.path.join(BASE_DIR, "reports", "alertas.log")
BLACKLIST_FILE = os.path.join(BASE_DIR, "data",    "blacklist_ips.json")
WHITELIST_FILE = os.path.join(BASE_DIR, "data",    "whitelist.json")

app = Flask(__name__)


# ── Helpers de base de datos ──────────────────────────────────────────────────

def _db_query(sql: str, params: tuple = ()) -> list:
    """Ejecuta una query de lectura y devuelve todas las filas."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except sqlite3.Error:
        return []


def _db_scalar(sql: str, params: tuple = (), default=0):
    """Ejecuta una query de lectura y devuelve un único valor escalar."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cur  = conn.cursor()
        cur.execute(sql, params)
        row = cur.fetchone()
        conn.close()
        return row[0] if row else default
    except sqlite3.Error:
        return default


# ── Funciones de datos ────────────────────────────────────────────────────────

def _get_stats() -> dict:
    total        = _db_scalar("SELECT COUNT(*) FROM dns_log")
    dominios     = _db_scalar("SELECT COUNT(DISTINCT dominio) FROM dns_log")
    no_auth      = _db_scalar("SELECT COUNT(*) FROM dns_log WHERE autorizado = 0")
    ips_unicas   = _db_scalar("SELECT COUNT(DISTINCT ip_origen) FROM dns_log")
    return {
        "total_consultas": total,
        "dominios_unicos": dominios,
        "no_autorizados":  no_auth,
        "ips_activas":     ips_unicas,
    }


def _get_dns_recent(limit: int = 50) -> list:
    return _db_query(
        """
        SELECT timestamp, ip_origen, mac_origen, dominio, tipo_query, autorizado
        FROM dns_log
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )


def _get_alertas_dispositivos() -> list:
    """
    Extrae del log de texto plano las líneas de dispositivos NO AUTORIZADOS
    (escritas por whitelist.py) y las devuelve como lista de dicts.
    """
    alertas = []
    pattern = re.compile(
        r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] DNS \| Estado: NO_AUTORIZADO \| "
        r"IP: ([\d.]+) \| MAC: ([\S]+) \| Dominio: ([\S]+)"
    )
    try:
        with open(ALERTS_LOG, "r", encoding="utf-8") as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    alertas.append({
                        "timestamp":  m.group(1),
                        "ip_origen":  m.group(2),
                        "mac_origen": m.group(3),
                        "dominio":    m.group(4),
                    })
    except FileNotFoundError:
        pass

    # Deduplicar por IP (mantener la más reciente)
    visto: dict = {}
    for a in reversed(alertas):
        visto[a["ip_origen"]] = a
    return list(reversed(list(visto.values())))


def _get_ips_peligrosas() -> list:
    """
    Cruza la blacklist con la base de datos DNS para saber si alguna
    consulta provino de (o fue hacia) una IP peligrosa.
    También devuelve la lista completa de IPs en la blacklist con su
    estado de detección.
    """
    try:
        with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
            blacklist = json.load(f).get("ips_peligrosas", [])
    except (FileNotFoundError, json.JSONDecodeError):
        blacklist = []

    # IPs que aparecen como origen en el log DNS
    ips_en_log = set()
    rows = _db_query("SELECT DISTINCT ip_origen FROM dns_log")
    for r in rows:
        ips_en_log.add(r["ip_origen"])

    resultado = []
    for entrada in blacklist:
        ip = entrada.get("ip", "")
        resultado.append({
            "ip":          ip,
            "tipo_riesgo": entrada.get("tipo_riesgo", "Desconocido"),
            "nivel":       entrada.get("nivel", "ALTO"),
            "fuente":      entrada.get("fuente", "Desconocida"),
            "detectada":   ip in ips_en_log,
        })
    return resultado


def _get_top_dominios(limit: int = 10) -> list:
    return _db_query(
        """
        SELECT dominio, COUNT(*) as total
        FROM dns_log
        GROUP BY dominio
        ORDER BY total DESC
        LIMIT ?
        """,
        (limit,)
    )


# ── Rutas Flask ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(_get_stats())


@app.route("/api/dns")
def api_dns():
    return jsonify(_get_dns_recent(50))


@app.route("/api/alertas")
def api_alertas():
    return jsonify(_get_alertas_dispositivos())


@app.route("/api/amenazas")
def api_amenazas():
    return jsonify(_get_ips_peligrosas())


@app.route("/api/top_dominios")
def api_top_dominios():
    return jsonify(_get_top_dominios(10))


@app.route("/api/dashboard")
def api_dashboard():
    """Endpoint unificado que retorna todos los datos en una sola llamada."""
    return jsonify({
        "stats":        _get_stats(),
        "dns_recent":   _get_dns_recent(50),
        "alertas":      _get_alertas_dispositivos(),
        "amenazas":     _get_ips_peligrosas(),
        "top_dominios": _get_top_dominios(10),
        "updated_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


# ── Punto de entrada ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  IDS Dashboard — Panel de Control Web")
    print("  Accede en: http://127.0.0.1:5000")
    print("  Presiona Ctrl+C para detener el dashboard.")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
