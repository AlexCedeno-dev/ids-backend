"""
============================================================
Sistema IDS Institucional
Módulo: email_alert.py
Descripción: Gestiona el envío de correos de alerta al administrador
             usando el servidor SMTP configurado en .env.
             Soporta tres tipos de alerta:
               - ADVERTENCIA: IP/MAC no autorizada detectada
               - EMERGENCIA:  Conexión a IP peligrosa
               - FORENSE:     Reporte con datos Whois/AbuseIPDB
============================================================
"""

import smtplib
import logging
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import config

logger = logging.getLogger("IDS.Email")


def _build_base_html(titulo: str, color_titulo: str, cuerpo_html: str) -> str:
    """Construye la plantilla HTML base para todos los correos."""
    return f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
      <div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;
                  box-shadow:0 2px 8px rgba(0,0,0,0.1);overflow:hidden;">
        <div style="background:{color_titulo};padding:20px;color:#fff;">
          <h2 style="margin:0;">🔒 {config.ORG_NAME} — Sistema IDS</h2>
          <h3 style="margin:4px 0 0;">{titulo}</h3>
        </div>
        <div style="padding:24px;">
          {cuerpo_html}
          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
          <p style="font-size:12px;color:#999;">
            Alerta generada automáticamente el {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br>
            Sistema IDS Institucional — Solo para uso educativo/corporativo autorizado.
          </p>
        </div>
      </div>
    </body></html>
    """


def _send(subject: str, html_body: str) -> bool:
    """
    Función interna que establece la conexión SMTP y envía el correo.
    Retorna True si fue exitoso, False si hubo error.
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = config.SMTP_USER
        msg["To"]      = config.ADMIN_EMAIL

        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
            server.ehlo()
            server.starttls()                              # Cifrado TLS
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.sendmail(config.SMTP_USER, config.ADMIN_EMAIL, msg.as_string())

        logger.info(f"Correo enviado a {config.ADMIN_EMAIL}: {subject}")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("Error de autenticación SMTP. Verifica SMTP_USER y SMTP_PASSWORD en .env")
    except smtplib.SMTPException as e:
        logger.error(f"Error SMTP al enviar correo: {e}")
    except Exception as e:
        logger.error(f"Error inesperado al enviar correo: {e}")
    return False


# ── Alerta 1: IP/MAC no autorizada ───────────────────────────────────────────

def alerta_dispositivo_no_autorizado(ip: str, mac: str) -> bool:
    """
    Envía alerta cuando se detecta un dispositivo con IP o MAC
    que no está en la lista blanca.
    """
    subject = f"⚠️ [IDS ADVERTENCIA] Dispositivo no autorizado — {ip}"
    cuerpo  = f"""
        <h4 style="color:#e67e22;">Dispositivo No Autorizado Detectado</h4>
        <table style="width:100%;border-collapse:collapse;">
          <tr style="background:#fdf3e3;">
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">IP Detectada</td>
            <td style="padding:10px;border:1px solid #ddd;">{ip}</td>
          </tr>
          <tr>
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">MAC Detectada</td>
            <td style="padding:10px;border:1px solid #ddd;">{mac}</td>
          </tr>
          <tr style="background:#fdf3e3;">
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">Fecha / Hora</td>
            <td style="padding:10px;border:1px solid #ddd;">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</td>
          </tr>
          <tr>
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">Acción Recomendada</td>
            <td style="padding:10px;border:1px solid #ddd;">Verificar físicamente el dispositivo y bloquear en switch si no es autorizado.</td>
          </tr>
        </table>
    """
    html = _build_base_html("⚠️ Advertencia de Seguridad", "#e67e22", cuerpo)
    return _send(subject, html)


# ── Alerta 2: IP peligrosa (Emergencia) ──────────────────────────────────────

def alerta_ip_peligrosa(ip_origen: str, mac_origen: str,
                         ip_destino: str, tipo_riesgo: str,
                         nivel: str) -> bool:
    """
    Envía alerta de emergencia cuando se detecta tráfico hacia
    una IP catalogada como maliciosa en la lista negra.
    """
    color_nivel = {"CRITICO": "#c0392b", "ALTO": "#e74c3c",
                   "MEDIO": "#e67e22", "DEMO": "#3498db"}.get(nivel, "#c0392b")

    subject = f"🚨 [IDS EMERGENCIA] Conexión a IP peligrosa — {ip_destino}"
    cuerpo  = f"""
        <h4 style="color:#c0392b;">🚨 Alerta de Emergencia — Conexión Maliciosa</h4>
        <table style="width:100%;border-collapse:collapse;">
          <tr style="background:#fdecea;">
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">IP Origen (Interno)</td>
            <td style="padding:10px;border:1px solid #ddd;">{ip_origen}</td>
          </tr>
          <tr>
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">MAC Origen</td>
            <td style="padding:10px;border:1px solid #ddd;">{mac_origen}</td>
          </tr>
          <tr style="background:#fdecea;">
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">IP Destino (Peligrosa)</td>
            <td style="padding:10px;border:1px solid #ddd;color:#c0392b;font-weight:bold;">{ip_destino}</td>
          </tr>
          <tr>
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">Tipo de Riesgo</td>
            <td style="padding:10px;border:1px solid #ddd;">{tipo_riesgo}</td>
          </tr>
          <tr style="background:#fdecea;">
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">Nivel de Amenaza</td>
            <td style="padding:10px;border:1px solid #ddd;">
              <span style="background:{color_nivel};color:#fff;padding:3px 10px;border-radius:4px;">
                {nivel}
              </span>
            </td>
          </tr>
          <tr>
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">Fecha / Hora</td>
            <td style="padding:10px;border:1px solid #ddd;">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</td>
          </tr>
        </table>
        <p style="color:#c0392b;font-weight:bold;margin-top:16px;">
          ⚡ Se adjuntará informe forense en correo separado con datos del proveedor.
        </p>
    """
    html = _build_base_html("🚨 Alerta de Emergencia", "#c0392b", cuerpo)
    return _send(subject, html)


# ── Alerta 3: Reporte forense ─────────────────────────────────────────────────

def alerta_forense(ip_peligrosa: str, datos_forenses: dict) -> bool:
    """
    Envía el reporte forense completo con datos Whois/AbuseIPDB
    del proveedor de la IP maliciosa.
    """
    # Extraer campos del reporte forense
    pais         = datos_forenses.get("pais",          "Desconocido")
    asn          = datos_forenses.get("asn",           "Desconocido")
    proveedor    = datos_forenses.get("proveedor",     "Desconocido")
    abuso_email  = datos_forenses.get("abuso_email",   "No disponible")
    abuso_url    = datos_forenses.get("abuso_url",     "No disponible")
    score_abuso  = datos_forenses.get("score_abuso",   "N/A")
    total_reports= datos_forenses.get("total_reportes","N/A")
    descripcion  = datos_forenses.get("descripcion",   "Sin descripción adicional")

    subject = f"🔎 [IDS FORENSE] Reporte de IP peligrosa — {ip_peligrosa}"
    cuerpo  = f"""
        <h4 style="color:#8e44ad;">🔎 Reporte Forense Automatizado</h4>
        <p>Se realizó consulta automática Whois / AbuseIPDB para la IP detectada:</p>
        <table style="width:100%;border-collapse:collapse;">
          <tr style="background:#f5eef8;">
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">IP Analizada</td>
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;color:#8e44ad;">{ip_peligrosa}</td>
          </tr>
          <tr>
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">País de Origen</td>
            <td style="padding:10px;border:1px solid #ddd;">{pais}</td>
          </tr>
          <tr style="background:#f5eef8;">
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">ASN (Red)</td>
            <td style="padding:10px;border:1px solid #ddd;">{asn}</td>
          </tr>
          <tr>
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">Proveedor / ISP</td>
            <td style="padding:10px;border:1px solid #ddd;">{proveedor}</td>
          </tr>
          <tr style="background:#f5eef8;">
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">Correo de Abuso</td>
            <td style="padding:10px;border:1px solid #ddd;">{abuso_email}</td>
          </tr>
          <tr>
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">URL de Reporte</td>
            <td style="padding:10px;border:1px solid #ddd;">
              <a href="{abuso_url}">{abuso_url}</a>
            </td>
          </tr>
          <tr style="background:#f5eef8;">
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">Score AbuseIPDB</td>
            <td style="padding:10px;border:1px solid #ddd;">{score_abuso} / 100</td>
          </tr>
          <tr>
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">Total Reportes</td>
            <td style="padding:10px;border:1px solid #ddd;">{total_reports}</td>
          </tr>
          <tr style="background:#f5eef8;">
            <td style="padding:10px;border:1px solid #ddd;font-weight:bold;">Descripción</td>
            <td style="padding:10px;border:1px solid #ddd;">{descripcion}</td>
          </tr>
        </table>
        <p style="margin-top:16px;">
          📧 Puedes reportar esta IP directamente al proveedor escribiendo a 
          <strong>{abuso_email}</strong> o usando la URL de reporte indicada arriba.
        </p>
    """
    html = _build_base_html("🔎 Reporte Forense", "#8e44ad", cuerpo)
    return _send(subject, html)
