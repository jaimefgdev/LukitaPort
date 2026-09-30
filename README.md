# LukitaPort

> **Advanced async port scanner with real-time UI, security audit, CVE lookup and enterprise-grade frontend architecture.**  
> **Escáner de puertos asíncrono con UI en tiempo real, auditoría de seguridad, búsqueda de CVEs y arquitectura frontend de nivel enterprise.**

---

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/FastAPI-0.111+-green?style=flat-square&logo=fastapi" />
  <img src="https://img.shields.io/badge/Vanilla_JS-ES_Modules-yellow?style=flat-square&logo=javascript" />
  <img src="https://img.shields.io/badge/CSP-script--src_'self'-red?style=flat-square" />
  <img src="https://img.shields.io/badge/License-Educational-lightgrey?style=flat-square" />
</p>

---

## Table of Contents · Índice

- [English](#english)
  - [Overview](#overview)
  - [Features](#features)
  - [Architecture](#architecture)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running](#running)
  - [API Reference](#api-reference)
  - [Frontend Modules](#frontend-modules)
  - [Security Design](#security-design)
  - [Export Formats](#export-formats)
  - [Docker](#docker)
  - [Project Structure](#project-structure)
- [Español](#español)
  - [Descripción general](#descripción-general)
  - [Funcionalidades](#funcionalidades)
  - [Arquitectura](#arquitectura)
  - [Requisitos](#requisitos)
  - [Instalación](#instalación)
  - [Configuración](#configuración)
  - [Ejecución](#ejecución)
  - [Referencia de la API](#referencia-de-la-api)
  - [Módulos del Frontend](#módulos-del-frontend)
  - [Diseño de Seguridad](#diseño-de-seguridad)
  - [Formatos de Exportación](#formatos-de-exportación)
  - [Docker](#docker-1)
  - [Estructura del Proyecto](#estructura-del-proyecto)

---

# English

## Overview

LukitaPort is a full-stack network reconnaissance tool built for **educational and authorised security research**. It streams port-scan results to the browser in real time over SSE, then automatically chains HTTP header auditing, technology fingerprinting, sensitive-path discovery, SSL/TLS analysis and NVD CVE lookup — all in a single, zero-dependency Vanilla JS frontend.

The backend is a Python / FastAPI async server. The frontend is a CSP-compliant ES-module application with rAF-batched rendering capable of smoothly handling 65,535-port full scans at 60 FPS.

> ⚠️ **For educational use only.** Only scan hosts you own or have explicit written permission to test.

---

## Features

### Scanning Engine
- **Async TCP port scanner** — `asyncio` connect probes, configurable timeout and concurrency
- **Scan modes** — Quick (top 100), Custom (user-defined range), Full (1–65535)
- **Scan profiles** — Normal, Stealth (random delays, slower rate), Aggressive (higher concurrency)
- **Anonymous mode** — forces Stealth profile and applies random per-port jitter
- **Real-time SSE stream** — server pushes `meta`, `port`, `done` events; browser renders rows as they arrive
- **GeoIP enrichment** — country, city, ASN, ISP, flag emoji from the resolved IP
- **nmap fingerprinting** — version detection (`-sV`) on open ports via subprocess bridge

### Security Audit (auto-launched on web ports 80, 443, 8080, 8443, 8888)
- **HTTP headers audit** — scores A+ → F, grades missing/present/dangerous headers
- **Technology detection** — ~60 signatures (servers, frameworks, CDNs, analytics) from JSON config
- **Sensitive path scan** — probes admin panels, backups, config files, `.git`, `.env` etc.
- **SSL/TLS analysis** — certificate chain, expiry, SANs, cipher, protocol versions, self-signed detection
- **CVE lookup** — NVD (nvd.nist.gov) batch queries per detected service/version with CVSS scoring

### Network Discovery & Recon
- **ICMP/ping sweep** — live host discovery across a CIDR range (e.g. `192.168.1.0/24`)
- **Subdomain enumeration** — crt.sh certificate transparency log lookup with DNS resolution
- **Screenshot capture** — Playwright Chromium headless, shared browser instance (one process per server lifetime)

### Exports
- **JSON** — full structured report with geo, versions and risk ratings
- **CSV** — flat table, quoted fields, comma-safe banners
- **HTML** — self-contained single-file report with embedded styles
- **Markdown** — server-rendered pentest-ready report
- **PDF** — server-rendered report via WeasyPrint

### Frontend Architecture
- **ES Modules** — `state.js`, `ui.js`, `api.js`, `templates.js`, `export.js`, `main.js`
- **rAF + DocumentFragment batching** — 60 FPS stable at 1,000 SSE events/second
- **Smart auto-scroll** — only follows new rows if the user was already near the bottom
- **Hermetic EventSource teardown** — null handlers before `.close()` on every scan stop (no memory leaks across repeated scans)
- **CSP `script-src 'self'` compliant** — zero `onclick`/`onmouseover` attributes, event delegation via `data-action` map
- **Non-blocking exports** — chunked `yieldToMain()` processing, 5,000 rows/chunk, spinner never freezes
- **Anti-XSS** — `escapeHTML()` + `safeHref()` on every backend string before `innerHTML` injection
- **i18n** — full ES / EN bilingual UI, switchable at runtime

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Browser (Vanilla JS ES Modules)                            │
│  ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌────────────┐   │
│  │ state.js │ │  ui.js   │ │templates.js│ │  export.js │   │
│  │ (store)  │ │ (render) │ │ (HTML tmpl)│ │ (chunked)  │   │
│  └────┬─────┘ └────┬─────┘ └─────┬──────┘ └─────┬──────┘   │
│       │             │              │               │          │
│  ┌────┴─────────────┴──────────────┴───────────────┴──────┐  │
│  │                   main.js  (event delegation)           │  │
│  │              api.js  (SSE + fetch)                      │  │
│  └─────────────────────────┬───────────────────────────────┘  │
└────────────────────────────│────────────────────────────────┘
                             │ HTTP / SSE
┌────────────────────────────┴────────────────────────────────┐
│  FastAPI (Python 3.11+)                                      │
│  ┌────────────┐ ┌────────────┐ ┌──────────────┐             │
│  │ scanner.py │ │ auditor.py │ │ ssl_analyzer │             │
│  │(async TCP) │ │(headers+   │ │   .py        │             │
│  │            │ │ paths+tech)│ └──────────────┘             │
│  └────────────┘ └────────────┘ ┌──────────────┐             │
│  ┌────────────┐ ┌────────────┐ │ cve_lookup   │             │
│  │ resolver.py│ │scan_service│ │   .py (NVD)  │             │
│  │(DNS+SSRF)  │ │.py (shots) │ └──────────────┘             │
│  └────────────┘ └────────────┘                              │
│  ┌────────────┐ ┌────────────┐ ┌──────────────┐             │
│  │  cache.py  │ │  models.py │ │pdf_generator │             │
│  │(TTL-LRU)   │ │ (Pydantic) │ │   .py        │             │
│  └────────────┘ └────────────┘ └──────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

---

## Requirements

### Backend
| Dependency | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Runtime |
| FastAPI | 0.111+ | Web framework |
| Uvicorn | 0.29+ | ASGI server |
| aiohttp | 3.9+ | Async HTTP (audit, CVE) |
| dnspython | 2.6+ | DNS resolution |
| geoip2 | 4.x | GeoIP database |
| WeasyPrint | 62+ | PDF generation |
| Playwright | 1.44+ | Screenshots (optional) |
| nmap | system | Fingerprinting (optional) |

### Frontend
No build step. No bundler. No npm. ES Modules loaded natively by the browser.

---

## Installation

### 1 · Clone

```bash
git clone https://github.com/jaimefg1888/lukitaport.git
cd lukitaport
```

### 2 · Python environment

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3 · Optional dependencies

**Playwright** (screenshots):
```bash
pip install playwright
playwright install chromium
```

**nmap** (fingerprinting):
```bash
# Debian / Ubuntu
sudo apt install nmap

# macOS
brew install nmap

# Windows
winget install Insecure.Nmap
```

**GeoIP database** (geo enrichment):
```bash
# Download GeoLite2-City.mmdb from maxmind.com and place it in:
./data/GeoLite2-City.mmdb
```

### 4 · Environment file

```bash
cp .env.example .env
# Edit .env — see Configuration section below
```

---

## Configuration

All configuration is through environment variables. Copy `.env.example` to `.env`.

```dotenv
# ── Access control (see security.py) ─────────────────────────────────────────
# API token (≥ 16 chars). Optional on 127.0.0.1 — a random one is generated
# and a login URL is printed at startup. MANDATORY on any other interface.
LUKITA_API_TOKEN=
LUKITA_HOST=127.0.0.1           # interface run.py listens on
LUKITA_PORT=8000
LUKITA_ALLOWED_HOSTS=           # Host header allow-list (default 127.0.0.1,localhost,::1)
LUKITA_ENABLE_ADMIN=false       # /api/admin/* only exists when true
LUKITA_RATE_LIMIT=120           # /api/ requests per client per minute
LUKITA_MAX_BODY_BYTES=5242880

# ── Resource limits (concurrent operations; extra requests get HTTP 429) ─────
LUKITA_MAX_SCANS=2
LUKITA_MAX_NMAP=1
LUKITA_MAX_SCREENSHOTS=2
LUKITA_MAX_AUDITS=2
LUKITA_MAX_SSL=2

# ── SSRF ─────────────────────────────────────────────────────────────────────
# Allow scanning private/internal IP addresses. "true" ONLY for local labs.
ALLOW_PRIVATE_IPS=false

# ── GeoIP (off by default; local MaxMind GeoLite2 files only) ────────────────
LUKITA_GEOIP_DB=                # e.g. ./data/GeoLite2-City.mmdb
LUKITA_GEOIP_ASN_DB=            # optional GeoLite2-ASN.mmdb

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL=INFO
```

### ALLOW_PRIVATE_IPS — SSRF Protection

| Value | Behaviour | Use case |
|---|---|---|
| `false` (default) | Blocks all RFC-1918, loopback, link-local, APIPA and reserved addresses. Returns HTTP 403. | Production, public-facing servers |
| `true` | Allows scanning any IP including internal ones | Local lab, educational use |

The SSRF check runs **after DNS resolution** to defend against DNS-rebinding attacks (a hostname that resolves to an internal IP is still blocked).

---

## Running

```bash
python run.py
```

`run.py` listens on `127.0.0.1:8000` by default and prints a login URL with a
token generated at each start (`http://127.0.0.1:8000/#token=…`) unless `LUKITA_API_TOKEN` is set, in
which case the UI asks for the token. It refuses to listen on any other
interface (`LUKITA_HOST=0.0.0.0`, a LAN IP…) without `LUKITA_API_TOKEN`.
It always runs a single worker (scan slots, caches and the browser are
per-process state).

API clients can authenticate with `Authorization: Bearer <token>`.

---

## API Reference

All endpoints return JSON unless noted otherwise.

### `GET /api/config`
Returns the port risk map used by the frontend.

### `GET /api/resolve?target={host}`
Resolves a hostname or IP. Returns `{ ip, hostname, input }` or `{ error }`.  
Returns **403** if the resolved IP is internal and `ALLOW_PRIVATE_IPS=false`.

### `GET /api/geoip?target={host}`
GeoIP lookup. Returns `{ country, city, asn, isp, flag }`.

### `GET /api/scan` · SSE
Streams port scan results as Server-Sent Events.

**Query params:**
| Param | Type | Default | Description |
|---|---|---|---|
| `target` | string | required | Host to scan |
| `mode` | `quick\|custom\|full` | `quick` | Port range preset |
| `profile` | `normal\|stealth\|aggressive` | `normal` | Scan behaviour |
| `port_start` | int | 1 | Start of custom range |
| `port_end` | int | 1024 | End of custom range |
| `timeout` | float | 1.0 | Per-port timeout in seconds |
| `anon` | `0\|1` | `0` | Force stealth + random delays |

**Event types:**
```
data: {"type": "meta",  "ip": "1.2.3.4", "hostname": "example.com", "total_ports": 100, "geo": {...}}
data: {"type": "port",  "port": 80, "state": "open", "service": "http", "response_time_ms": 42, "scanned": 1, "progress": 1.0}
data: {"type": "done"}
data: {"type": "port",  "error": "ssrf_blocked", "status": 403}
```

### `GET /api/fingerprint?target={host}&ports={csv}`
nmap `-sV` version detection on a list of open ports. Returns per-port `{ product, version, extrainfo, cpe }`.

### `GET /api/audit?target={host}&open_ports={csv}`
Full security audit. Returns `{ headers, technologies, paths }`.

### `GET /api/ssl?target={host}&open_ports={csv}`
SSL/TLS certificate analysis per HTTPS port.

### `POST /api/cve/batch`
NVD CVE batch lookup.  
Body: `{ "80": { "name": "nginx", "version": "1.24.0" }, ... }`

### `GET /api/discover?cidr={cidr}`
ICMP ping sweep of a CIDR range. Returns `{ alive: [{ip, rtt_ms}], alive_count, total_hosts }`.

### `GET /api/subdomains?domain={domain}`
crt.sh + DNS resolution subdomain enumeration.

### `POST /api/screenshot/capture?target={host}&port={port}`
Trigger a Playwright screenshot in the background.

### `GET /api/screenshot?target={host}`
Retrieve a previously captured screenshot as `image/png`.

### `POST /api/export/pdf`
Server-side PDF report generation via WeasyPrint.

### `POST /api/export/md`
Server-side Markdown report generation.

### `GET /api/admin/status`
Health / readiness check. Returns Playwright status, cache stats, `allow_private_ips` value.

---

## Frontend Modules

| Module | Responsibility |
|---|---|
| `state.js` | Single source of truth — `state` object, `getRisk()`, `initConfig()` |
| `ui.js` | DOM helpers, toast, rendering (rAF batching, smart scroll), audit render, `copyText` |
| `templates.js` | Pure template functions, `escapeHTML`, `safeHref`, zero inline handlers |
| `api.js` | SSE scan lifecycle, hermetic EventSource teardown, all `fetch` calls |
| `export.js` | Chunked async exports (JSON, CSV, HTML) + server-side PDF / Markdown |
| `main.js` | App entry point, event delegation (`data-action` map), static listeners |

### Event Delegation

Instead of `onclick` attributes, all dynamically-rendered interactive elements use `data-action`:

```html
<!-- Copy button (no onclick) -->
<button data-action="copy" data-copy-text="nginx config here">Copy nginx</button>

<!-- Scan a discovered host (no onclick) -->
<div data-action="scan-host" data-host="192.168.1.1">192.168.1.1</div>

<!-- Launch CVE lookup (no onclick, no window.* global) -->
<button data-action="launch-cve">Search CVEs</button>
```

A single listener on `document.body` dispatches to `_ACTION_HANDLERS`:

```js
document.body.addEventListener('click', e => {
    const el = e.target.closest('[data-action]');
    if (el) _ACTION_HANDLERS[el.dataset.action]?.(el, e);
});
```

---

## Security Design

### SSRF Prevention (`resolver.py`)
Checks resolved IP against six `ipaddress` properties before any connection is made:

| Property | Covers |
|---|---|
| `is_loopback` | `127.0.0.0/8`, `::1` |
| `is_private` | `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` |
| `is_link_local` | `169.254.0.0/16` (incl. AWS metadata `169.254.169.254`), `fe80::/10` |
| `is_reserved` | `0.0.0.0/8`, `240.0.0.0/4` |
| `is_multicast` | `224/4`, `ff00::/8` |
| `is_unspecified` | `0.0.0.0`, `::` |

The check runs post-DNS so a hostname that DNS-rebinds to `10.0.0.1` is still blocked.

### CSP Compliance (`templates.js`, `main.js`)
The frontend is fully compatible with:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```
- Zero `onclick`, `onmouseover`, `onmouseout` attributes in any generated HTML
- Zero `window.*` global function assignments
- Hover states for dynamic components delivered via CSS class (`.btn-cve-launch:hover`)
- Screenshot blob URLs created with `URL.createObjectURL()`, appended via DOM API

### Anti-XSS (`templates.js`)
Every backend string entering `innerHTML` passes through `escapeHTML()` (replaces `& < > " '`).  
External URLs pass through `safeHref()` (rejects `javascript:`, `data:`, `vbscript:`).

### Memory Safety (`api.js`)
EventSource teardown on every scan stop:
```js
es.onmessage = null;  // 1. Null handlers first (breaks GC root)
es.onerror   = null;
es.onopen    = null;
es.close();           // 2. Close TCP stream
state.eventSource = null; // 3. Release JS reference
```

---

## Export Formats

| Format | Engine | Blocking? | Notes |
|---|---|---|---|
| JSON | Client-side | No (chunked) | Full report with geo, risk, versions |
| CSV | Client-side | No (chunked) | Quoted fields, comma-safe banners |
| HTML | Client-side | No (chunked + prebuilt rows) | Self-contained, no external deps |
| Markdown | Server-side | No (async fetch) | Pentest-report structure |
| PDF | Server-side | No (async fetch) | WeasyPrint, styled report |

All client-side exports use `yieldToMain()` (setTimeout 0 ms) every 5,000 rows to keep the UI responsive during large exports.

---

## Docker

```bash
export LUKITA_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build
```

Then open `http://127.0.0.1:8000` and enter the token. The compose file
publishes the port on `127.0.0.1` only, refuses to start without
`LUKITA_API_TOKEN`, runs as an unprivileged user with all capabilities
dropped, a read-only filesystem and `no-new-privileges`.

---

## Project Structure

```
lukitaport/
│
├── main.py                  # FastAPI app, all endpoints, lifespan
├── scanner.py               # Async TCP port scanner
├── auditor.py               # HTTP headers + tech detection + path scan
├── ssl_analyzer.py          # SSL/TLS certificate analysis
├── cve_lookup.py            # NVD API client with exponential backoff
├── scan_service.py          # Screenshot capture, GeoIP, nmap bridge
├── resolver.py              # DNS resolution + SSRF protection
├── cache.py                 # TTL-LRU screenshot cache
├── models.py                # Pydantic v2 request/response models
├── config.py                # PORT_RISK map
├── logging_config.py        # Structured JSON logging
├── pdf_generator.py         # WeasyPrint PDF renderer
├── tech_signatures.json     # Technology detection signatures
│
├── static/                  # Frontend (served by FastAPI)
│   ├── index.html
│   ├── styles.css
│   ├── state.js
│   ├── ui.js
│   ├── api.js
│   ├── templates.js
│   ├── export.js
│   └── main.js
│
├── data/
│   └── GeoLite2-City.mmdb   # MaxMind GeoIP database (not included)
│
├── .env.example
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

---

# Español

## Descripción general

LukitaPort es una herramienta de reconocimiento de red full-stack diseñada para **uso educativo e investigación de seguridad autorizada**. Envía resultados de escaneo de puertos al navegador en tiempo real mediante SSE y encadena automáticamente auditoría de cabeceras HTTP, fingerprinting de tecnologías, descubrimiento de rutas sensibles, análisis SSL/TLS y búsqueda de CVEs en NVD — todo en un frontend Vanilla JS de cero dependencias.

El backend es un servidor Python/FastAPI asíncrono. El frontend es una aplicación de ES Modules compatible con CSP, con renderizado en lotes mediante rAF que gestiona escaneos completos de 65.535 puertos a 60 FPS de forma fluida.

> ⚠️ **Solo para uso educativo.** Escanea únicamente hosts que sean de tu propiedad o para los que tengas permiso escrito explícito.

---

## Funcionalidades

### Motor de Escaneo
- **Escáner TCP asíncrono** — sondas de conexión `asyncio`, timeout y concurrencia configurables
- **Modos de escaneo** — Rápido (top 100), Personalizado (rango definido por el usuario), Completo (1–65535)
- **Perfiles** — Normal, Stealth (delays aleatorios, tasa reducida), Agresivo (mayor concurrencia)
- **Modo anónimo** — fuerza el perfil Stealth y aplica jitter aleatorio por puerto
- **Stream SSE en tiempo real** — el servidor envía eventos `meta`, `port`, `done`; el navegador renderiza filas al recibirlos
- **Enriquecimiento GeoIP** — país, ciudad, ASN, ISP, emoji de bandera desde la IP resuelta
- **Fingerprinting con nmap** — detección de versiones (`-sV`) en puertos abiertos mediante subproceso

### Auditoría de Seguridad (lanzada automáticamente en puertos web 80, 443, 8080, 8443, 8888)
- **Auditoría de cabeceras HTTP** — puntuación de A+ a F, clasifica cabeceras ausentes/presentes/peligrosas
- **Detección de tecnologías** — ~60 firmas (servidores, frameworks, CDNs, analíticas) desde config JSON
- **Escaneo de rutas sensibles** — sondea paneles admin, backups, ficheros de configuración, `.git`, `.env`, etc.
- **Análisis SSL/TLS** — cadena de certificados, caducidad, SANs, cifrado, versiones de protocolo, detección de autofirmados
- **Búsqueda de CVEs** — consultas por lotes a NVD (nvd.nist.gov) por servicio/versión detectados con puntuación CVSS

### Descubrimiento de Red y Reconocimiento
- **Barrido ICMP/ping** — descubrimiento de hosts activos en un rango CIDR (p.ej. `192.168.1.0/24`)
- **Enumeración de subdominios** — consulta a logs de transparencia de certificados crt.sh con resolución DNS
- **Captura de capturas de pantalla** — Playwright Chromium headless, instancia de browser compartida (un proceso por vida del servidor)

### Exportaciones
- **JSON** — informe estructurado completo con geo, versiones y clasificaciones de riesgo
- **CSV** — tabla plana, campos entrecomillados, banners seguros ante comas
- **HTML** — informe autocontenido en un único fichero con estilos embebidos
- **Markdown** — informe renderizado en servidor listo para pentesting
- **PDF** — informe renderizado en servidor via WeasyPrint

### Arquitectura Frontend
- **ES Modules** — `state.js`, `ui.js`, `api.js`, `templates.js`, `export.js`, `main.js`
- **Batching rAF + DocumentFragment** — 60 FPS estables a 1.000 eventos SSE por segundo
- **Auto-scroll inteligente** — solo sigue las nuevas filas si el usuario ya estaba cerca del fondo
- **Teardown hermético del EventSource** — null de handlers antes de `.close()` en cada parada de escaneo (sin fugas de memoria entre escaneos sucesivos)
- **Cumplimiento CSP `script-src 'self'`** — cero atributos `onclick`/`onmouseover`, delegación de eventos via mapa `data-action`
- **Exportaciones no bloqueantes** — procesamiento por chunks con `yieldToMain()`, 5.000 filas por chunk, el spinner nunca se congela
- **Anti-XSS** — `escapeHTML()` + `safeHref()` en cada string del backend antes de inyectarlo en `innerHTML`
- **i18n** — UI bilingüe ES/EN completa, switchable en tiempo de ejecución

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│  Navegador (Vanilla JS ES Modules)                          │
│  ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌────────────┐   │
│  │ state.js │ │  ui.js   │ │templates.js│ │  export.js │   │
│  │ (estado) │ │(renderiz)│ │(plantillas)│ │ (por chunks│   │
│  └────┬─────┘ └────┬─────┘ └─────┬──────┘ └─────┬──────┘   │
│       │             │              │               │          │
│  ┌────┴─────────────┴──────────────┴───────────────┴──────┐  │
│  │             main.js  (delegación de eventos)            │  │
│  │           api.js  (SSE + fetch)                         │  │
│  └─────────────────────────┬───────────────────────────────┘  │
└────────────────────────────│────────────────────────────────┘
                             │ HTTP / SSE
┌────────────────────────────┴────────────────────────────────┐
│  FastAPI (Python 3.11+)                                      │
│  ┌────────────┐ ┌────────────┐ ┌──────────────┐             │
│  │ scanner.py │ │ auditor.py │ │ ssl_analyzer │             │
│  │ (TCP asíc.)│ │(cabeceras+ │ │   .py        │             │
│  │            │ │rutas+tech) │ └──────────────┘             │
│  └────────────┘ └────────────┘ ┌──────────────┐             │
│  ┌────────────┐ ┌────────────┐ │ cve_lookup   │             │
│  │ resolver.py│ │scan_service│ │   .py (NVD)  │             │
│  │(DNS+SSRF)  │ │.py (shots) │ └──────────────┘             │
│  └────────────┘ └────────────┘                              │
│  ┌────────────┐ ┌────────────┐ ┌──────────────┐             │
│  │  cache.py  │ │  models.py │ │pdf_generator │             │
│  │(TTL-LRU)   │ │ (Pydantic) │ │   .py        │             │
│  └────────────┘ └────────────┘ └──────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

---

## Requisitos

### Backend
| Dependencia | Versión | Uso |
|---|---|---|
| Python | 3.11+ | Runtime |
| FastAPI | 0.111+ | Framework web |
| Uvicorn | 0.29+ | Servidor ASGI |
| aiohttp | 3.9+ | HTTP asíncrono (auditoría, CVE) |
| dnspython | 2.6+ | Resolución DNS |
| geoip2 | 4.x | Base de datos GeoIP |
| WeasyPrint | 62+ | Generación de PDF |
| Playwright | 1.44+ | Capturas de pantalla (opcional) |
| nmap | sistema | Fingerprinting (opcional) |

### Frontend
Sin build. Sin bundler. Sin npm. ES Modules cargados nativamente por el navegador.

---

## Instalación

### 1 · Clonar

```bash
git clone https://github.com/jaimefg1888/lukitaport.git
cd lukitaport
```

### 2 · Entorno Python

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3 · Dependencias opcionales

**Playwright** (capturas de pantalla):
```bash
pip install playwright
playwright install chromium
```

**nmap** (fingerprinting):
```bash
# Debian / Ubuntu
sudo apt install nmap

# macOS
brew install nmap

# Windows
winget install Insecure.Nmap
```

**Base de datos GeoIP** (enriquecimiento geográfico):
```bash
# Descarga GeoLite2-City.mmdb desde maxmind.com y colócala en:
./data/GeoLite2-City.mmdb
```

### 4 · Fichero de entorno

```bash
cp .env.example .env
# Edita .env — consulta la sección Configuración a continuación
```

---

## Configuración

Toda la configuración se realiza mediante variables de entorno. Copia `.env.example` a `.env`.

```dotenv
# ── Control de acceso (ver security.py) ──────────────────────────────────────
# Token de la API (≥ 16 caracteres). Opcional en 127.0.0.1: se genera uno
# aleatorio y se imprime una URL de acceso al arrancar. OBLIGATORIO en otra interfaz.
LUKITA_API_TOKEN=
LUKITA_HOST=127.0.0.1           # interfaz en la que escucha run.py
LUKITA_PORT=8000
LUKITA_ALLOWED_HOSTS=           # Hosts permitidos (defecto 127.0.0.1,localhost,::1)
LUKITA_ENABLE_ADMIN=false       # /api/admin/* solo existe si es true
LUKITA_RATE_LIMIT=120           # peticiones /api/ por cliente y minuto
LUKITA_MAX_BODY_BYTES=5242880

# ── Límites (operaciones simultáneas; el exceso recibe HTTP 429) ─────────────
LUKITA_MAX_SCANS=2
LUKITA_MAX_NMAP=1
LUKITA_MAX_SCREENSHOTS=2
LUKITA_MAX_AUDITS=2
LUKITA_MAX_SSL=2

# ── SSRF ─────────────────────────────────────────────────────────────────────
# Permite escanear IPs privadas/internas. "true" SOLO en laboratorios locales.
ALLOW_PRIVATE_IPS=false

# ── GeoIP (desactivada por defecto; solo ficheros locales GeoLite2) ──────────
LUKITA_GEOIP_DB=                # p. ej. ./data/GeoLite2-City.mmdb
LUKITA_GEOIP_ASN_DB=            # GeoLite2-ASN.mmdb opcional

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL=INFO
```

### ALLOW_PRIVATE_IPS — Protección contra SSRF

| Valor | Comportamiento | Caso de uso |
|---|---|---|
| `false` (defecto) | Bloquea todas las IPs RFC-1918, loopback, link-local, APIPA y reservadas. Devuelve HTTP 403. | Producción, servidores públicos |
| `true` | Permite escanear cualquier IP incluyendo las internas | Lab local, uso educativo |

La verificación SSRF se ejecuta **después de la resolución DNS** para defenderse de ataques de DNS-rebinding (un hostname que resuelve a una IP interna sigue siendo bloqueado).

---

## Ejecución

```bash
python run.py
```

`run.py` escucha en `127.0.0.1:8000` por defecto e imprime una URL de acceso
con un token generado en cada arranque (`http://127.0.0.1:8000/#token=…`), salvo que esté definido
`LUKITA_API_TOKEN`, en cuyo caso la interfaz pide el token. Se niega a
escuchar en cualquier otra interfaz (`LUKITA_HOST=0.0.0.0`, una IP de la
LAN…) sin `LUKITA_API_TOKEN`. Siempre usa un único worker.

Los clientes de la API pueden autenticarse con `Authorization: Bearer <token>`.

---

## Referencia de la API

Todos los endpoints devuelven JSON salvo indicación contraria.

### `GET /api/config`
Devuelve el mapa de riesgo de puertos usado por el frontend.

### `GET /api/resolve?target={host}`
Resuelve un hostname o IP. Devuelve `{ ip, hostname, input }` o `{ error }`.  
Devuelve **403** si la IP resuelta es interna y `ALLOW_PRIVATE_IPS=false`.

### `GET /api/geoip?target={host}`
Consulta GeoIP. Devuelve `{ country, city, asn, isp, flag }`.

### `GET /api/scan` · SSE
Envía los resultados del escaneo como Server-Sent Events.

**Parámetros query:**
| Parámetro | Tipo | Defecto | Descripción |
|---|---|---|---|
| `target` | string | obligatorio | Host a escanear |
| `mode` | `quick\|custom\|full` | `quick` | Preset de rango de puertos |
| `profile` | `normal\|stealth\|aggressive` | `normal` | Comportamiento del escaneo |
| `port_start` | int | 1 | Inicio del rango personalizado |
| `port_end` | int | 1024 | Fin del rango personalizado |
| `timeout` | float | 1.0 | Timeout por puerto en segundos |
| `anon` | `0\|1` | `0` | Forzar stealth + delays aleatorios |

**Tipos de evento:**
```
data: {"type": "meta",  "ip": "1.2.3.4", "hostname": "ejemplo.com", "total_ports": 100, "geo": {...}}
data: {"type": "port",  "port": 80, "state": "open", "service": "http", "response_time_ms": 42, ...}
data: {"type": "done"}
data: {"type": "port",  "error": "ssrf_blocked", "status": 403}
```

### `GET /api/fingerprint?target={host}&ports={csv}`
Detección de versiones nmap `-sV` sobre una lista de puertos abiertos.

### `GET /api/audit?target={host}&open_ports={csv}`
Auditoría de seguridad completa. Devuelve `{ headers, technologies, paths }`.

### `GET /api/ssl?target={host}&open_ports={csv}`
Análisis de certificados SSL/TLS por puerto HTTPS.

### `POST /api/cve/batch`
Búsqueda por lotes de CVEs en NVD.  
Cuerpo: `{ "80": { "name": "nginx", "version": "1.24.0" }, ... }`

### `GET /api/discover?cidr={cidr}`
Barrido ping ICMP en un rango CIDR. Devuelve `{ alive: [{ip, rtt_ms}], ... }`.

### `GET /api/subdomains?domain={domain}`
Enumeración de subdominios vía crt.sh + resolución DNS.

### `POST /api/screenshot/capture?target={host}&port={port}`
Lanza una captura de pantalla Playwright en segundo plano.

### `GET /api/screenshot?target={host}`
Recupera una captura de pantalla previa como `image/png`.

### `POST /api/export/pdf`
Generación de informe PDF en servidor via WeasyPrint.

### `POST /api/export/md`
Generación de informe Markdown en servidor.

### `GET /api/admin/status`
Health check. Devuelve estado de Playwright, estadísticas de caché, valor de `allow_private_ips`.

---

## Módulos del Frontend

| Módulo | Responsabilidad |
|---|---|
| `state.js` | Fuente única de verdad — objeto `state`, `getRisk()`, `initConfig()` |
| `ui.js` | Helpers DOM, toast, renderizado (batching rAF, scroll inteligente), render de auditoría, `copyText` |
| `templates.js` | Funciones de plantilla puras, `escapeHTML`, `safeHref`, cero handlers inline |
| `api.js` | Ciclo de vida del SSE, teardown hermético del EventSource, todas las llamadas `fetch` |
| `export.js` | Exportaciones asíncronas por chunks (JSON, CSV, HTML) + PDF/Markdown en servidor |
| `main.js` | Punto de entrada, delegación de eventos (mapa `data-action`), listeners estáticos |

### Delegación de Eventos

En lugar de atributos `onclick`, todos los elementos interactivos renderizados dinámicamente usan `data-action`:

```html
<!-- Botón copiar (sin onclick) -->
<button data-action="copy" data-copy-text="config nginx aquí">Copiar nginx</button>

<!-- Escanear host descubierto (sin onclick) -->
<div data-action="scan-host" data-host="192.168.1.1">192.168.1.1</div>

<!-- Lanzar búsqueda CVE (sin onclick, sin global window.*) -->
<button data-action="launch-cve">Buscar CVEs</button>
```

Un único listener en `document.body` despacha a `_ACTION_HANDLERS`:

```js
document.body.addEventListener('click', e => {
    const el = e.target.closest('[data-action]');
    if (el) _ACTION_HANDLERS[el.dataset.action]?.(el, e);
});
```

---

## Diseño de Seguridad

### Prevención SSRF (`resolver.py`)
Verifica la IP resuelta contra seis propiedades de `ipaddress` antes de realizar cualquier conexión:

| Propiedad | Cubre |
|---|---|
| `is_loopback` | `127.0.0.0/8`, `::1` |
| `is_private` | `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` |
| `is_link_local` | `169.254.0.0/16` (incl. metadata AWS `169.254.169.254`), `fe80::/10` |
| `is_reserved` | `0.0.0.0/8`, `240.0.0.0/4` |
| `is_multicast` | `224/4`, `ff00::/8` |
| `is_unspecified` | `0.0.0.0`, `::` |

La verificación se ejecuta post-DNS, por lo que un hostname que DNS-rebinda a `10.0.0.1` sigue siendo bloqueado.

### Cumplimiento CSP (`templates.js`, `main.js`)
El frontend es totalmente compatible con:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```
- Cero atributos `onclick`, `onmouseover`, `onmouseout` en ningún HTML generado
- Cero asignaciones de funciones globales `window.*`
- Estados hover de componentes dinámicos entregados via clase CSS (`.btn-cve-launch:hover`)
- URLs blob de capturas de pantalla creadas con `URL.createObjectURL()`, añadidas via API DOM

### Anti-XSS (`templates.js`)
Cada string del backend que entra en `innerHTML` pasa por `escapeHTML()` (reemplaza `& < > " '`).  
Las URLs externas pasan por `safeHref()` (rechaza `javascript:`, `data:`, `vbscript:`).

### Seguridad de Memoria (`api.js`)
Teardown del EventSource en cada parada de escaneo:
```js
es.onmessage = null;  // 1. Null handlers primero (rompe la raíz del GC)
es.onerror   = null;
es.onopen    = null;
es.close();           // 2. Cierra el stream TCP
state.eventSource = null; // 3. Libera la referencia JS
```

---

## Formatos de Exportación

| Formato | Motor | ¿Bloqueante? | Notas |
|---|---|---|---|
| JSON | Cliente | No (por chunks) | Informe completo con geo, riesgo, versiones |
| CSV | Cliente | No (por chunks) | Campos entrecomillados, banners seguros |
| HTML | Cliente | No (chunks + filas preconstruidas) | Autocontenido, sin dependencias externas |
| Markdown | Servidor | No (fetch asíncrono) | Estructura de informe de pentest |
| PDF | Servidor | No (fetch asíncrono) | WeasyPrint, informe con estilos |

Todas las exportaciones del lado cliente usan `yieldToMain()` (setTimeout 0 ms) cada 5.000 filas para mantener la UI responsiva durante exportaciones grandes.

---

## Docker

```bash
export LUKITA_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build
```

Después abre `http://127.0.0.1:8000` e introduce el token. El compose publica
el puerto solo en `127.0.0.1`, se niega a arrancar sin `LUKITA_API_TOKEN` y
ejecuta la app con un usuario sin privilegios, sin capabilities, con sistema
de ficheros de solo lectura y `no-new-privileges`.

---

## Estructura del Proyecto

```
lukitaport/
│
├── main.py                  # App FastAPI, todos los endpoints, lifespan
├── scanner.py               # Escáner TCP asíncrono
├── auditor.py               # Cabeceras HTTP + detección de tecnologías + rutas
├── ssl_analyzer.py          # Análisis de certificados SSL/TLS
├── cve_lookup.py            # Cliente API NVD con backoff exponencial
├── scan_service.py          # Capturas de pantalla, GeoIP, puente nmap
├── resolver.py              # Resolución DNS + protección SSRF
├── cache.py                 # Caché TTL-LRU de capturas de pantalla
├── models.py                # Modelos Pydantic v2 de request/response
├── config.py                # Mapa PORT_RISK
├── logging_config.py        # Logs estructurados en JSON
├── pdf_generator.py         # Renderizador PDF con WeasyPrint
├── tech_signatures.json     # Firmas de detección de tecnologías
│
├── static/                  # Frontend (servido por FastAPI)
│   ├── index.html
│   ├── styles.css
│   ├── state.js
│   ├── ui.js
│   ├── api.js
│   ├── templates.js
│   ├── export.js
│   └── main.js
│
├── data/
│   └── GeoLite2-City.mmdb   # Base de datos MaxMind GeoIP (no incluida)
│
├── .env.example
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

<p align="center">
  <sub>LukitaPort · jaimefg1888 · For educational use only · Solo para uso educativo</sub>
</p>
