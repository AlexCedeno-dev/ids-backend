"""
============================================================
Sistema IDS Institucional
Módulo: threat_intel.py
Descripción: Gestiona la inteligencia de amenazas (Threat Intelligence).
             Carga la lista negra de IPs maliciosas desde blacklist_ips.json
             y verifica si una IP de destino es peligrosa.
             Al detectar una, dispara alerta de emergencia por correo.
============================================================
"""

import json
import logging
import threading
from datetime import datetime

import config
import email_alert

logger = logging.getLogger("IDS.ThreatIntel")

# Mapa ip_peligrosa -> datos de amenaza para búsqueda O(1)
_blacklist: dict[str, dict] = {}


def cargar_blacklist() -> None:
    """
    Lee blacklist_ips.json y carga las IPs peligrosas en memoria.
    Debe llamarse una vez al iniciar el sistema.
    """
    global _blacklist
    try:
        with open(config.BLACKLIST_FILE, "r", encoding="utf-8") as f:
            datos = json.load(f)

        for entrada in datos.get("ips_peligrosas", []):
            ip = entrada.get("ip", "").strip()
            if ip:
                _blacklist[ip] = entrada

        logger.info(f"Blacklist cargada: {len(_blacklist)} IPs peligrosas registradas.")
    except FileNotFoundError:
        logger.error(f"No se encontró blacklist en: {config.BLACKLIST_FILE}")
    except json.JSONDecodeError as e:
        logger.error(f"Error al parsear blacklist_ips.json: {e}")


def verificar_ip_destino(ip_origen: str, mac_origen: str, ip_destino: str) -> bool:
    """
    Verifica si la IP de destino está en la lista negra.
    Si lo está, registra la alerta y dispara correo de emergencia.

    Retorna True si la IP es peligrosa, False si es segura.
    """
    if ip_destino not in _blacklist:
        return False  # IP segura, no hacer nada

    amenaza = _blacklist[ip_destino]
    tipo_riesgo = amenaza.get("tipo_riesgo", "Desconocido")
    nivel       = amenaza.get("nivel",       "ALTO")
    fuente      = amenaza.get("fuente",      "Desconocida")
    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logger.critical(
        f"[AMENAZA DETECTADA] {timestamp} | "
        f"Origen: {ip_origen} ({mac_origen}) → "
        f"Destino peligroso: {ip_destino} | "
        f"Riesgo: {tipo_riesgo} [{nivel}] | Fuente: {fuente}"
    )

    # Escribir en log de alertas
    linea = (
        f"[{timestamp}] AMENAZA | Nivel: {nivel} | "
        f"Origen: {ip_origen} ({mac_origen}) | "
        f"Destino: {ip_destino} | Riesgo: {tipo_riesgo} | "
        f"Fuente: {fuente}\n"
    )
    try:
        with open(config.ALERTS_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(linea)
    except IOError as e:
        logger.error(f"Error al escribir alerta en log: {e}")

    # Disparar alerta de emergencia en hilo separado
    hilo = threading.Thread(
        target=email_alert.alerta_ip_peligrosa,
        args=(ip_origen, mac_origen, ip_destino, tipo_riesgo, nivel),
        daemon=True
    )
    hilo.start()

    return True


def get_info_amenaza(ip: str) -> dict:
    """
    Retorna los datos de amenaza de una IP peligrosa.
    Si no está en la lista, retorna dict vacío.
    """
    return _blacklist.get(ip, {})


def get_total_blacklist() -> int:
    """Retorna el total de IPs en la lista negra."""
    return len(_blacklist)
