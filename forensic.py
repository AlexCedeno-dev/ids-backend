"""
============================================================
Sistema IDS Institucional
Módulo: forensic.py
Descripción: Módulo de automatización forense.
             Cuando se detecta una IP peligrosa, consulta automáticamente:
               1. ipwhois (RDAP/Whois) — sin API key necesaria
               2. AbuseIPDB — si hay API key configurada en .env
             Extrae: país, ASN, proveedor, contacto de abuso.
             Envía el reporte forense completo al administrador.
============================================================
"""

import logging
import threading
import requests
from ipwhois import IPWhois

import config
import email_alert

logger = logging.getLogger("IDS.Forense")


def _consultar_ipwhois(ip: str) -> dict:
    """
    Consulta información Whois/RDAP de la IP usando la librería ipwhois.
    No requiere API key. Funciona para IPs públicas.
    """
    resultado = {}
    try:
        obj  = IPWhois(ip)
        data = obj.lookup_rdap(depth=1)

        resultado["pais"]     = data.get("network", {}).get("country", "Desconocido")
        resultado["asn"]      = f"AS{data.get('asn', 'N/A')} — {data.get('asn_description', '')}"
        resultado["proveedor"]= data.get("network", {}).get("name", "Desconocido")

        # Intentar obtener correo de abuso desde los objetos de la red
        abuso_emails = []
        for obj_key, obj_data in data.get("objects", {}).items():
            for email in obj_data.get("contact", {}).get("email", []):
                if "abuse" in email.get("value", "").lower():
                    abuso_emails.append(email["value"])

        resultado["abuso_email"] = abuso_emails[0] if abuso_emails else "No disponible"
        resultado["abuso_url"]   = f"https://search.arin.net/rdap/#?query={ip}"

        logger.info(f"[FORENSE Whois] IP: {ip} | País: {resultado['pais']} | ASN: {resultado['asn']}")

    except Exception as e:
        logger.warning(f"[FORENSE Whois] No se pudo obtener info para {ip}: {e}")
        resultado = {
            "pais":        "Error en consulta",
            "asn":         "Error en consulta",
            "proveedor":   "Error en consulta",
            "abuso_email": "No disponible",
            "abuso_url":   f"https://www.abuseipdb.com/check/{ip}"
        }
    return resultado


def _consultar_abuseipdb(ip: str) -> dict:
    """
    Consulta AbuseIPDB para obtener score de reputación, total de reportes
    y descripción del último reporte.
    Requiere ABUSEIPDB_API_KEY en .env (registro gratuito en abuseipdb.com).
    """
    resultado = {
        "score_abuso":     "N/A (sin API key)",
        "total_reportes":  "N/A",
        "descripcion":     "Configura ABUSEIPDB_API_KEY en .env para ver detalles.",
        "abuso_url":       f"https://www.abuseipdb.com/check/{ip}"
    }

    if not config.ABUSEIPDB_API_KEY:
        logger.debug("ABUSEIPDB_API_KEY no configurada, omitiendo consulta.")
        return resultado

    try:
        url     = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key":    config.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})

        resultado["score_abuso"]    = data.get("abuseConfidenceScore", "N/A")
        resultado["total_reportes"] = data.get("totalReports", "N/A")
        resultado["abuso_url"]      = f"https://www.abuseipdb.com/check/{ip}"

        # Último comentario de reporte disponible
        reportes = data.get("reports", [])
        if reportes:
            resultado["descripcion"] = reportes[0].get("comment", "Sin descripción")[:300]

        logger.info(
            f"[FORENSE AbuseIPDB] IP: {ip} | "
            f"Score: {resultado['score_abuso']} | "
            f"Reportes: {resultado['total_reportes']}"
        )

    except requests.RequestException as e:
        logger.warning(f"[FORENSE AbuseIPDB] Error al consultar API para {ip}: {e}")

    return resultado


def analizar_ip_forense(ip_peligrosa: str) -> None:
    """
    Función principal del módulo forense.
    Combina resultados de ipwhois y AbuseIPDB, y envía el reporte
    al administrador por correo.
    
    Se llama en un hilo separado para no bloquear el sniffer.
    """
    logger.info(f"[FORENSE] Iniciando análisis forense para: {ip_peligrosa}")

    # 1. Consultar ipwhois (Whois/RDAP)
    datos_whois   = _consultar_ipwhois(ip_peligrosa)

    # 2. Consultar AbuseIPDB
    datos_abuso   = _consultar_abuseipdb(ip_peligrosa)

    # 3. Combinar resultados
    datos_forenses = {**datos_whois, **datos_abuso}

    # 4. Enviar reporte por correo
    email_alert.alerta_forense(ip_peligrosa, datos_forenses)

    logger.info(f"[FORENSE] Reporte forense enviado para: {ip_peligrosa}")


def analizar_ip_forense_async(ip_peligrosa: str) -> None:
    """
    Lanza el análisis forense en un hilo separado para no
    bloquear el proceso de captura de paquetes.
    """
    hilo = threading.Thread(
        target=analizar_ip_forense,
        args=(ip_peligrosa,),
        daemon=True
    )
    hilo.start()
