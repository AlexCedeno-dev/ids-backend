"""
============================================================
Sistema IDS Institucional
Archivo: main.py
Descripción: Punto de entrada principal del sistema.
             Inicializa todos los módulos, muestra el banner,
             inicia la captura de paquetes y gestiona la salida
             limpia con Ctrl+C.

Uso:
    sudo python3 main.py              # Modo captura normal
    sudo python3 main.py --reporte    # Solo mostrar reporte DNS
    sudo python3 main.py --test-email # Probar envío de correo
============================================================
"""

import sys
import logging
import threading
import time
from datetime import datetime

# ── Configurar logging antes de importar módulos ──────────────────────────────
import config

logging.basicConfig(
    level    = getattr(logging, config.LOG_LEVEL, logging.INFO),
    format   = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt  = "%Y-%m-%d %H:%M:%S",
    handlers = [
        logging.StreamHandler(sys.stdout),                         # Consola
        logging.FileHandler(config.ALERTS_LOG_FILE, encoding="utf-8")  # Archivo
    ]
)

logger = logging.getLogger("IDS.Main")

# ── Importar módulos del IDS ──────────────────────────────────────────────────
import whitelist
import dns_monitor
import threat_intel
import email_alert
import sniffer


BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║         SISTEMA IDS INSTITUCIONAL  v1.0                      ║
║         Detección de Intrusos en Red Local                   ║
║         Solo para uso educativo / entorno controlado         ║
╚══════════════════════════════════════════════════════════════╝
"""


def mostrar_banner() -> None:
    print(BANNER)
    print(f"  Organización  : {config.ORG_NAME}")
    print(f"  Interfaz      : {config.NETWORK_INTERFACE}")
    print(f"  Admin Email   : {config.ADMIN_EMAIL}")
    print(f"  Inicio        : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"  Log           : {config.ALERTS_LOG_FILE}")
    print("─" * 64)


def inicializar_modulos() -> None:
    """Carga listas blancas, negras y DB antes de iniciar la captura."""
    logger.info("Inicializando módulos del IDS...")
    whitelist.cargar_whitelist()
    threat_intel.cargar_blacklist()
    dns_monitor.inicializar_db()

    logger.info(
        f"Sistema listo | "
        f"IPs autorizadas: {whitelist.get_total_autorizados()} | "
        f"IPs peligrosas: {threat_intel.get_total_blacklist()}"
    )


def mostrar_reporte() -> None:
    """Muestra el reporte DNS en consola (modo --reporte)."""
    registros = dns_monitor.obtener_reporte(limit=20)
    stats     = dns_monitor.obtener_estadisticas()

    print("\n══ REPORTE DNS ══════════════════════════════════════════════")
    print(f"  Total consultas  : {stats.get('total_consultas', 0)}")
    print(f"  Dominios únicos  : {stats.get('dominios_unicos', 0)}")
    print(f"  No autorizados   : {stats.get('no_autorizados', 0)}")
    print("─" * 64)
    print(f"  {'TIMESTAMP':<20} {'IP ORIGEN':<16} {'DOMINIO':<35} {'TIPO'}")
    print("─" * 64)

    for r in registros:
        estado = "" if r["autorizado"] else "⚠ "
        print(
            f"  {r['timestamp']:<20} "
            f"{r['ip_origen']:<16} "
            f"{estado}{r['dominio']:<35} "
            f"{r['tipo_query']}"
        )
    print("═" * 64 + "\n")


def test_email() -> None:
    """Envía un correo de prueba para verificar configuración SMTP."""
    logger.info("Enviando correo de prueba...")
    ok = email_alert.alerta_dispositivo_no_autorizado(
        ip  = "192.168.1.254",
        mac = "de:ad:be:ef:00:01"
    )
    if ok:
        print(f"\n✅ Correo de prueba enviado a: {config.ADMIN_EMAIL}")
    else:
        print(f"\n❌ Error al enviar correo. Verifica credenciales en .env")


def hilo_estadisticas() -> None:
    """
    Hilo secundario que imprime estadísticas en consola cada 60 segundos.
    Permite ver actividad sin revisar logs manualmente.
    """
    while True:
        time.sleep(60)
        stats = dns_monitor.obtener_estadisticas()
        logger.info(
            f"[Estadísticas] Consultas DNS: {stats.get('total_consultas', 0)} | "
            f"Dominios únicos: {stats.get('dominios_unicos', 0)} | "
            f"No autorizados: {stats.get('no_autorizados', 0)}"
        )


def main() -> None:
    mostrar_banner()

    # ── Modo --reporte ────────────────────────────────────────────────────────
    if "--reporte" in sys.argv:
        dns_monitor.inicializar_db()
        mostrar_reporte()
        return

    # ── Modo --test-email ─────────────────────────────────────────────────────
    if "--test-email" in sys.argv:
        test_email()
        return

    # ── Modo normal: iniciar captura ──────────────────────────────────────────
    inicializar_modulos()

    # Hilo de estadísticas periódicas
    t_stats = threading.Thread(target=hilo_estadisticas, daemon=True)
    t_stats.start()

    print("\n  🟢 Sistema activo. Monitoreando red...")
    print("  Presiona Ctrl+C para detener.\n")

    try:
        sniffer.iniciar_captura()
    except KeyboardInterrupt:
        print("\n\n  🔴 Sistema detenido por el usuario.")
        mostrar_reporte()
        logger.info("Sistema IDS detenido.")


if __name__ == "__main__":
    main()
