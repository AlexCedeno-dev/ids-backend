"""
============================================================
Sistema IDS Institucional
Módulo: whitelist.py
Descripción: Gestiona la lista blanca de dispositivos autorizados.
             Concepto IAA: Identificación, Autenticación, Autorización.
             Anti-spam: cada IP no autorizada solo genera UNA alerta
             por sesión para no saturar el correo del administrador.
============================================================
"""

import json
import logging
from typing import Optional

import config
import email_alert

logger = logging.getLogger("IDS.Whitelist")

_ips_autorizadas:  set = set()
_macs_autorizadas: set = set()
_mapa_dispositivos: dict = {}

# Anti-spam: IPs que ya recibieron alerta en esta sesión
_ips_ya_alertadas: set = set()


def cargar_whitelist() -> None:
    global _ips_autorizadas, _macs_autorizadas, _mapa_dispositivos
    try:
        with open(config.WHITELIST_FILE, "r", encoding="utf-8") as f:
            datos = json.load(f)
        for d in datos.get("dispositivos", []):
            ip  = d.get("ip",  "").strip().lower()
            mac = d.get("mac", "").strip().lower()
            if ip:
                _ips_autorizadas.add(ip)
                _mapa_dispositivos[ip] = d
            if mac:
                _macs_autorizadas.add(mac)
        logger.info(
            f"Whitelist cargada: {len(_ips_autorizadas)} IPs | "
            f"{len(_macs_autorizadas)} MACs autorizadas."
        )
    except FileNotFoundError:
        logger.error(f"No se encontró whitelist en: {config.WHITELIST_FILE}")
    except json.JSONDecodeError as e:
        logger.error(f"Error al parsear whitelist.json: {e}")


def es_autorizado(ip: str, mac: str) -> bool:
    ip  = ip.strip().lower()
    mac = mac.strip().lower()

    ip_ok  = ip  in _ips_autorizadas
    mac_ok = mac in _macs_autorizadas

    if ip_ok and mac_ok:
        nombre = _mapa_dispositivos.get(ip, {}).get("nombre", "Desconocido")
        logger.debug(f"[AUTORIZADO] {nombre} — IP: {ip} | MAC: {mac}")
        return True

    # fe80:: es link-local IPv6 (siempre privada); si además la MAC ya está
    # registrada, el dispositivo es conocido aunque tenga una IPv6 distinta.
    if ip.startswith("fe80::") or mac_ok:
        logger.debug(f"[AUTORIZADO-IPV6] IP: {ip} | MAC: {mac} — link-local o MAC conocida.")
        return True

    # IPs internas que requieren validación completa:
    #   192.168.x.x  → IPv4 LAN
    #   fe80::       → IPv6 link-local  (ya resuelto arriba, pero incluido por completitud)
    #   2806:        → IPv6 global de la red local
    es_interna = (
        ip.startswith("192.168.")
        or ip.startswith("fe80::")
        or ip.startswith("2806:")
    )

    if not es_interna:
        logger.debug(f"[EXTERNO] IP: {ip} | MAC: {mac} — tráfico externo, ignorado.")
        return False

    razon = []
    if not ip_ok:
        razon.append(f"IP '{ip}' no registrada")
    if not mac_ok:
        razon.append(f"MAC '{mac}' no registrada")

    logger.warning(
        f"[NO AUTORIZADO] IP: {ip} | MAC: {mac} | Razón: {', '.join(razon)}"
    )

    # Anti-spam: solo un correo por IP interna por sesión
    if ip not in _ips_ya_alertadas:
        _ips_ya_alertadas.add(ip)
        logger.info(f"[ALERTA] Enviando correo de advertencia para IP: {ip}")
        import threading
        threading.Thread(
            target=email_alert.alerta_dispositivo_no_autorizado,
            args=(ip, mac),
            daemon=True
        ).start()
    else:
        logger.debug(f"[ANTI-SPAM] Alerta ya enviada para {ip}, omitiendo.")

    return False


def get_info_dispositivo(ip: str) -> Optional[dict]:
    return _mapa_dispositivos.get(ip.strip().lower())


def get_total_autorizados() -> int:
    return len(_ips_autorizadas)
