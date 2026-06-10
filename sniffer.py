"""
============================================================
Sistema IDS Institucional
Módulo: sniffer.py
Descripción: Núcleo de captura de paquetes usando Scapy.
             Intercepta tráfico en la interfaz configurada y delega
             cada paquete a los módulos correspondientes:
               - whitelist.py   → validar IP/MAC
               - dns_monitor.py → registrar consultas DNS
               - threat_intel.py→ verificar IPs peligrosas
               - forensic.py    → análisis forense si hay amenaza
============================================================
"""

import logging
from datetime import datetime

from scapy.all import sniff, ARP, DNS, DNSQR, IP, Ether, UDP, TCP

import config
import whitelist
import dns_monitor
import threat_intel
import forensic

logger = logging.getLogger("IDS.Sniffer")

# IPs propias del sistema/red que se omiten para evitar falsos positivos
_IPS_IGNORAR = {"0.0.0.0", "255.255.255.255", "224.0.0.1", "224.0.0.251"}

# Registro de amenazas ya analizadas para no repetir correos
_amenazas_notificadas: set[str] = set()


def _procesar_paquete(pkt) -> None:
    """
    Callback invocado por Scapy por cada paquete capturado.
    Extrae IP y MAC de origen, IP de destino y delega a los módulos.
    """
    try:
        # ── Extraer capa Ethernet (MAC) ─────────────────────────────────────
        if not pkt.haslayer(Ether):
            return  # Sin capa Ethernet no podemos obtener MAC

        mac_origen = pkt[Ether].src.lower()

        # ── Extraer capa IP ─────────────────────────────────────────────────
        if not pkt.haslayer(IP):
            return  # Solo procesamos tráfico IPv4

        ip_origen  = pkt[IP].src
        ip_destino = pkt[IP].dst

        # Ignorar IPs de broadcast y multicast
        if ip_origen in _IPS_IGNORAR or ip_destino in _IPS_IGNORAR:
            return

        # ── Módulo 1: Validar lista blanca ──────────────────────────────────
        autorizado = whitelist.es_autorizado(ip_origen, mac_origen)

        # ── Módulo 2: Monitoreo DNS ──────────────────────────────────────────
        # Detectar paquetes DNS (UDP puerto 53)
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            dominio    = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            tipo_query = _tipo_dns(pkt[DNSQR].qtype)

            if dominio:  # Ignorar consultas vacías
                dns_monitor.registrar_consulta(
                    ip_origen   = ip_origen,
                    mac_origen  = mac_origen,
                    dominio     = dominio,
                    tipo_query  = tipo_query,
                    autorizado  = autorizado
                )

        # ── Módulo 3: Verificar IP destino contra blacklist ──────────────────
        clave_amenaza = f"{ip_origen}→{ip_destino}"
        if ip_destino not in _amenazas_notificadas:
            es_peligrosa = threat_intel.verificar_ip_destino(
                ip_origen  = ip_origen,
                mac_origen = mac_origen,
                ip_destino = ip_destino
            )

            if es_peligrosa:
                _amenazas_notificadas.add(ip_destino)  # Evitar spam de alertas

                # ── Módulo 4: Análisis forense asíncrono ─────────────────────
                forensic.analizar_ip_forense_async(ip_destino)

    except Exception as e:
        # No dejar que un error en un paquete tumbe todo el sniffer
        logger.debug(f"Error procesando paquete: {e}")


def _tipo_dns(qtype: int) -> str:
    """Convierte el código numérico de tipo DNS a su nombre."""
    tipos = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX",
             2: "NS", 6: "SOA", 16: "TXT", 12: "PTR"}
    return tipos.get(qtype, str(qtype))


def iniciar_captura() -> None:
    """
    Inicia la captura de paquetes en la interfaz configurada.
    Bloquea el hilo actual (llamar desde main.py en hilo dedicado).
    
    Filtro BPF: captura IP, ARP y DNS para minimizar carga del sistema.
    """
    interfaz = config.NETWORK_INTERFACE
    logger.info(f"Iniciando captura en interfaz: {interfaz}")
    logger.info("Filtro activo: IP, ARP, DNS — Solo tráfico de red local")
    logger.info("Presiona Ctrl+C en main.py para detener el sistema.")

    try:
        sniff(
            iface   = interfaz,
            filter  = "ip or arp",          # Filtro BPF eficiente
            prn     = _procesar_paquete,    # Callback por cada paquete
            store   = False,                # No guardar en RAM
            count   = 0                     # Capturar indefinidamente
        )
    except PermissionError:
        logger.error(
            "Permisos insuficientes para capturar paquetes.\n"
            "Ejecuta el sistema con: sudo python3 main.py"
        )
    except OSError as e:
        logger.error(
            f"Error de red al iniciar captura: {e}\n"
            f"Verifica que la interfaz '{interfaz}' existe con: ip link show"
        )
