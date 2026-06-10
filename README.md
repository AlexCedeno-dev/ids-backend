# 🔒 Sistema IDS Institucional v1.0

> Sistema de Detección de Intrusos (IDS) para red local.  
> Desarrollado con Python y Scapy para entorno educativo y de laboratorio.  
> **Solo para uso en redes propias o con autorización explícita.**

---

## 📋 Tabla de Contenidos

1. [Arquitectura del Sistema](#arquitectura)
2. [Requisitos del Sistema](#requisitos)
3. [Instalación](#instalación)
4. [Configuración (.env)](#configuración)
5. [Uso del Sistema](#uso)
6. [Módulos Funcionales](#módulos)
7. [Estructura de Archivos](#estructura)
8. [Troubleshooting](#troubleshooting)

---

## Arquitectura

```
Red Local (tráfico)
        │
        ▼
  [sniffer.py]  ← Scapy captura paquetes en la interfaz de red
        │
        ├──► [whitelist.py]    Valida IP/MAC contra lista blanca
        │         └──► [email_alert.py]  Alerta: dispositivo no autorizado
        │
        ├──► [dns_monitor.py]  Registra dominios DNS consultados
        │         └──► [logs.db / alertas.log]
        │
        ├──► [threat_intel.py] Verifica IP destino contra lista negra
        │         └──► [email_alert.py]  Alerta: IP peligrosa (Emergencia)
        │
        └──► [forensic.py]     Consulta Whois + AbuseIPDB
                  └──► [email_alert.py]  Reporte forense al admin
```

**Flujo OSI:**
- Capa 2 (Enlace): captura dirección MAC origen desde trama Ethernet
- Capa 3 (Red): captura IP origen y destino desde cabecera IPv4
- Capa 4 (Transporte): identifica TCP/UDP para filtrar DNS (puerto 53)
- Capa 7 (Aplicación): extrae nombre de dominio de consultas DNS

---

## Requisitos

### Sistema Operativo
- **Linux** (Ubuntu 20.04+, Debian 11+, Kali Linux) — Recomendado
- Python 3.9 o superior

### Dependencias del Sistema

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv libpcap-dev -y

# Verificar versión de Python
python3 --version
```

### Dependencias Python
Ver `requirements.txt`. Se instalan automáticamente con pip.

---

## Instalación

### 1. Clonar o descomprimir el proyecto

```bash
# Si usas Git
git clone https://github.com/tu-usuario/ids_project.git
cd ids_project

# O descomprimir el ZIP
unzip ids_project.zip && cd ids_project
```

### 2. Crear entorno virtual (recomendado)

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar variables de entorno

```bash
# Copiar el archivo de ejemplo
cp .env.example .env

# Editar con tus datos reales
nano .env
```

### 5. Configurar whitelist

Edita `data/whitelist.json` y agrega las IPs y MACs de tus equipos:

```bash
nano data/whitelist.json
```

Para obtener la MAC de un equipo en tu red:
```bash
# Ver tu propia MAC
ip link show

# Ver MACs de equipos detectados en la red
arp -a
```

### 6. Obtener tu interfaz de red

```bash
ip link show
# Busca eth0, enp3s0, wlan0, etc.
```

---

## Configuración

Edita el archivo `.env` con tus datos:

```ini
# Servidor SMTP (Gmail como ejemplo)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tucorreo@gmail.com
SMTP_PASSWORD=tu_contrasena_de_aplicacion   # Ver nota abajo

# Correo del administrador
ADMIN_EMAIL=admin@tudominio.com

# Nombre de la organización
ORG_NAME=Mi Institución Educativa

# Interfaz de red (resultado de: ip link show)
NETWORK_INTERFACE=eth0

# Opcional: API de AbuseIPDB (gratis en abuseipdb.com)
ABUSEIPDB_API_KEY=
```

### ⚠️ Contraseña de Aplicación Gmail

Gmail requiere una **contraseña de aplicación** (no tu contraseña normal):

1. Ir a: `myaccount.google.com` → Seguridad
2. Activar **Verificación en 2 pasos**
3. Ir a: **Contraseñas de aplicaciones**
4. Generar una para "Correo" → copiar la clave de 16 caracteres
5. Pegar esa clave como `SMTP_PASSWORD` en tu `.env`

---

## Uso

### Iniciar el IDS (requiere sudo para captura de paquetes)

```bash
sudo python3 main.py
```

### Ver reporte DNS en consola

```bash
sudo python3 main.py --reporte
```

### Probar envío de correo

```bash
python3 main.py --test-email
```

### Detener el sistema

```
Ctrl + C
```
Al detener, se muestra automáticamente el reporte DNS del periodo.

---

## Módulos

| Módulo | Descripción | Alerta generada |
|---|---|---|
| `whitelist.py` | Valida IP y MAC contra lista blanca | ⚠️ Advertencia |
| `dns_monitor.py` | Registra dominios DNS visitados | Log en DB y archivo |
| `threat_intel.py` | Cruza IP destino con lista negra | 🚨 Emergencia |
| `forensic.py` | Whois + AbuseIPDB de IP peligrosa | 🔎 Reporte forense |
| `email_alert.py` | Envía correos HTML al administrador | — |
| `sniffer.py` | Captura paquetes con Scapy | — |
| `config.py` | Carga configuración desde `.env` | — |

---

## Estructura de Archivos

```
ids_project/
├── main.py              # Punto de entrada
├── sniffer.py           # Captura de paquetes (Scapy)
├── whitelist.py         # Módulo listas blancas IP/MAC
├── dns_monitor.py       # Módulo monitoreo DNS
├── threat_intel.py      # Módulo IPs peligrosas
├── forensic.py          # Módulo análisis forense
├── email_alert.py       # Módulo envío de correos
├── config.py            # Configuración centralizada
├── data/
│   ├── whitelist.json   # Lista blanca de dispositivos
│   ├── blacklist_ips.json  # Lista negra de IPs maliciosas
│   └── logs.db          # Base de datos SQLite (auto-generada)
├── reports/
│   └── alertas.log      # Log de eventos en texto plano
├── .env                 # Credenciales reales (NO subir a Git)
├── .env.example         # Plantilla de configuración
├── requirements.txt     # Dependencias Python
└── README.md
```

---

## Troubleshooting

### ❌ `PermissionError` al iniciar captura
```bash
# Siempre ejecutar con sudo
sudo python3 main.py
```

### ❌ `OSError: No such device` — interfaz no encontrada
```bash
# Ver interfaces disponibles
ip link show
# Editar NETWORK_INTERFACE en .env
```

### ❌ Error de autenticación SMTP
- Verifica que usas **contraseña de aplicación**, no tu contraseña normal de Gmail.
- Verifica que `SMTP_USER` y `SMTP_PASSWORD` están correctos en `.env`.
- Desactiva el antivirus/firewall local temporalmente para probar.

### ❌ Las alertas llegan a Spam
- Abre el correo → marcarlo como "No es spam"
- Agregar `SMTP_USER` a contactos del admin
- En Gmail: Configuración → Filtros → "Nunca enviar a spam" para ese remitente

### ❌ `ModuleNotFoundError: No module named 'scapy'`
```bash
# Asegúrate de estar en el entorno virtual
source venv/bin/activate
pip install -r requirements.txt
```

### ❌ La base de datos no se crea
```bash
# Verificar permisos en la carpeta data/
ls -la data/
chmod 755 data/
```

---

## 📚 Fuentes y Librerías

- Scapy: https://scapy.net/
- python-dotenv: https://pypi.org/project/python-dotenv/
- ipwhois: https://pypi.org/project/ipwhois/
- AbuseIPDB API: https://docs.abuseipdb.com/
- colorama: https://pypi.org/project/colorama/

---

## 📷 Capturas para Manual de Usuario

Para el manual, se recomienda capturar pantalla de:

1. `sudo python3 main.py` → Banner inicial con módulos cargados
2. Terminal mostrando alerta en tiempo real de dispositivo no autorizado
3. Terminal mostrando alerta de IP peligrosa detectada
4. `sudo python3 main.py --reporte` → Tabla de dominios DNS
5. Correo de advertencia recibido en Gmail
6. Correo de emergencia recibido con datos de amenaza
7. Correo forense con datos Whois/AbuseIPDB
8. Archivo `data/whitelist.json` editado con un nuevo dispositivo
9. Archivo `reports/alertas.log` con eventos registrados
10. Comando `ip link show` mostrando la interfaz de red activa

---

*Sistema IDS Institucional — Proyecto educativo de Ciberseguridad*
