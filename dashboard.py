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

from flask import Flask, jsonify, request
from flask_cors import CORS

# Rutas absolutas para que el dashboard funcione independientemente
# del directorio de trabajo desde el que se lance
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DB_FILE        = os.path.join(BASE_DIR, "data",    "logs.db")
ALERTS_LOG     = os.path.join(BASE_DIR, "reports", "alertas.log")
BLACKLIST_FILE = os.path.join(BASE_DIR, "data",    "blacklist_ips.json")
WHITELIST_FILE = os.path.join(BASE_DIR, "data",    "whitelist.json")
ENV_FILE       = os.path.join(BASE_DIR, ".env")

app = Flask(__name__)
CORS(app)


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


_DNS_NOISE = (
    "gvt2", "gvt3", "beacons", "googlevideo",
    "doubleclick", "gstatic", "ggpht", "googlesyndication",
)


def _cargar_mac_nombres() -> dict:
    """Devuelve un mapa MAC (minúsculas) → nombre desde la whitelist."""
    try:
        data = _read_json(WHITELIST_FILE)
        return {
            d["mac"].strip().lower(): d.get("nombre", "Desconocido")
            for d in data.get("dispositivos", [])
            if d.get("mac")
        }
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return {}


def _resolver_nombre(ip: str, mac: str, mac_nombres: dict) -> str:
    if mac in mac_nombres:
        return mac_nombres[mac]
    if ip.startswith("fe80::"):
        return "Dispositivo Local"
    if ip.startswith("192.168."):
        return "Red Local " + ip.replace(".", "")[-4:]
    return "Equipo " + ip[-4:]


def _get_dns_recent(limit: int = 50) -> list:
    # Traer más filas de las necesarias para que al deduplicar/filtrar
    # el resultado final siga siendo representativo.
    rows = _db_query(
        """
        SELECT timestamp, ip_origen, mac_origen, dominio, tipo_query, autorizado
        FROM dns_log
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit * 6,)
    )

    mac_nombres = _cargar_mac_nombres()
    seen_domains: set = set()
    result = []
    for row in rows:
        dominio = row.get("dominio", "")
        if any(n in dominio for n in _DNS_NOISE):
            continue
        if dominio in seen_domains:
            continue
        seen_domains.add(dominio)
        ip  = row.get("ip_origen",  "")
        mac = row.get("mac_origen", "").lower()
        row["dispositivo_nombre"] = _resolver_nombre(ip, mac, mac_nombres)
        result.append(row)
        if len(result) >= limit:
            break
    return result


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

    # IPs que ya fueron detectadas como destino peligroso (fuente de verdad)
    ips_detectadas = set()
    for r in _db_query("SELECT DISTINCT ip_destino FROM amenazas_log"):
        ips_detectadas.add(r["ip_destino"])

    resultado = []
    for entrada in blacklist:
        ip = entrada.get("ip", "")
        resultado.append({
            "ip":          ip,
            "tipo_riesgo": entrada.get("tipo_riesgo", "Desconocido"),
            "nivel":       entrada.get("nivel", "ALTO"),
            "fuente":      entrada.get("fuente", "Desconocida"),
            "detectada":   ip in ips_detectadas,
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


# ── Helpers de archivos JSON ──────────────────────────────────────────────────

def _read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    return (
        len(parts) == 4
        and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    )


# ── Rutas — Whitelist ─────────────────────────────────────────────────────────

@app.route("/api/whitelist", methods=["GET"])
def api_whitelist_get():
    try:
        return jsonify(_read_json(WHITELIST_FILE))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/whitelist", methods=["POST"])
def api_whitelist_post():
    body = request.get_json(silent=True) or {}
    print(f"[DEBUG] POST /api/whitelist — body recibido: {body}")

    # Acepta tanto {tipo, valor, descripcion} (frontend) como {nombre, ip, mac} (legado)
    nombre = (body.get("descripcion") or body.get("nombre") or "").strip()
    ip     = (body.get("valor")       or body.get("ip")     or "").strip()
    mac    = (body.get("mac")         or "00:00:00:00:00:00").strip().lower()
    rol    = (body.get("rol")         or "usuario").strip()

    if not nombre or not ip:
        return jsonify({"error": "Campos requeridos: descripcion (o nombre) y valor (o ip)"}), 400
    if not _valid_ip(ip):
        return jsonify({"error": f"IP inválida: {ip}"}), 400

    try:
        data = _read_json(WHITELIST_FILE)
        dispositivos = data.get("dispositivos", [])

        if any(d.get("ip") == ip for d in dispositivos):
            return jsonify({"error": f"La IP {ip} ya existe en la whitelist"}), 409

        dispositivo = {"nombre": nombre, "ip": ip, "mac": mac, "rol": rol}
        dispositivos.append(dispositivo)
        data["dispositivos"] = dispositivos
        _write_json(WHITELIST_FILE, data)
        return jsonify({"success": True, "mensaje": "Dispositivo agregado", "dispositivo": dispositivo}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/whitelist/<ip>", methods=["DELETE"])
def api_whitelist_delete(ip: str):
    try:
        data = _read_json(WHITELIST_FILE)
        dispositivos = data.get("dispositivos", [])
        originales = len(dispositivos)
        data["dispositivos"] = [d for d in dispositivos if d.get("ip") != ip]

        if len(data["dispositivos"]) == originales:
            return jsonify({"error": f"IP {ip} no encontrada en la whitelist"}), 404

        _write_json(WHITELIST_FILE, data)
        return jsonify({"ok": True, "eliminada": ip})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Rutas — Blacklist ─────────────────────────────────────────────────────────

@app.route("/api/blacklist", methods=["GET"])
def api_blacklist_get():
    try:
        return jsonify(_read_json(BLACKLIST_FILE))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/blacklist", methods=["POST"])
def api_blacklist_post():
    body = request.get_json(silent=True) or {}
    ip          = (body.get("ip")          or "").strip()
    tipo_riesgo = (body.get("tipo_riesgo") or "Desconocido").strip()
    nivel       = (body.get("nivel")       or "ALTO").strip().upper()
    fuente      = (body.get("fuente")      or "Manual").strip()

    if not ip:
        return jsonify({"error": "Campo requerido: ip"}), 400
    if not _valid_ip(ip):
        return jsonify({"error": f"IP inválida: {ip}"}), 400
    if nivel not in {"CRITICO", "ALTO", "MEDIO", "BAJO", "DEMO"}:
        return jsonify({"error": "nivel debe ser CRITICO, ALTO, MEDIO, BAJO o DEMO"}), 400

    try:
        data = _read_json(BLACKLIST_FILE)
        ips_peligrosas = data.get("ips_peligrosas", [])

        if any(e.get("ip") == ip for e in ips_peligrosas):
            return jsonify({"error": f"La IP {ip} ya existe en la blacklist"}), 409

        entrada = {"ip": ip, "tipo_riesgo": tipo_riesgo, "nivel": nivel, "fuente": fuente}
        ips_peligrosas.append(entrada)
        data["ips_peligrosas"] = ips_peligrosas
        _write_json(BLACKLIST_FILE, data)
        return jsonify({"ok": True, "entrada": entrada}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/blacklist/<ip>", methods=["DELETE"])
def api_blacklist_delete(ip: str):
    try:
        data = _read_json(BLACKLIST_FILE)
        ips = data.get("ips_peligrosas", [])
        originales = len(ips)
        data["ips_peligrosas"] = [e for e in ips if e.get("ip") != ip]
        if len(data["ips_peligrosas"]) == originales:
            return jsonify({"error": f"IP {ip} no encontrada en la blacklist"}), 404
        _write_json(BLACKLIST_FILE, data)
        return jsonify({"ok": True, "eliminada": ip})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Ruta — Configuración email ────────────────────────────────────────────────

@app.route("/api/config/email", methods=["POST"])
def api_config_email():
    body  = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()

    if not email or "@" not in email:
        return jsonify({"error": "Email inválido"}), 400

    try:
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        updated = False
        new_lines = []
        for line in lines:
            if line.startswith("ADMIN_EMAIL="):
                new_lines.append(f"ADMIN_EMAIL={email}\n")
                updated = True
            else:
                new_lines.append(line)

        if not updated:
            new_lines.append(f"ADMIN_EMAIL={email}\n")

        with open(ENV_FILE, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        return jsonify({"ok": True, "admin_email": email})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Ruta — Limpiar logs ───────────────────────────────────────────────────────

@app.route("/api/logs/clear", methods=["POST"])
def api_logs_clear():
    try:
        conn = sqlite3.connect(DB_FILE)
        cur  = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS dns_log")
        cur.execute("""
            CREATE TABLE dns_log (
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
        return jsonify({"ok": True, "mensaje": "Base de datos reinicializada"})
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500


# ── Punto de entrada ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  IDS Dashboard — Panel de Control Web")
    print("  Accede en: http://127.0.0.1:5000")
    print("  Presiona Ctrl+C para detener el dashboard.")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
