"""
main.py
───────
LukitaPort v2 — FastAPI application entry point.

Route handlers are intentionally thin:
  1. Validate input (via helper functions).
  2. Delegate to the service layer / module functions.
  3. Return a typed JSON response.

All business logic lives in scan_service.py and the dedicated module files.

Lifespan — what happens at startup / shutdown
──────────────────────────────────────────────
Startup:
  1. Configure structured JSON logging.
  2. Try to start a shared Playwright + Chromium instance.
     If playwright is not installed the server still starts; screenshots
     fall back to the per-request launch strategy in scan_service.py.
  3. Register the browser with scan_service.set_browser() so every
     take_screenshot call reuses the single Chromium process.
  4. Start a background task that evicts expired screenshot-cache entries
     every 5 minutes.

Shutdown:
  1. Cancel the eviction task.
  2. Close the shared Playwright browser and stop the playwright instance,
     preventing orphan Chromium processes after Uvicorn stops.

SSRF protection
───────────────
After every resolve_target() call, check whether the resolved IP is an
internal/private address.  If so, return HTTP 403 Forbidden.

The check is skipped when ``ALLOW_PRIVATE_IPS=true`` is set in the
environment — useful for scanning internal lab networks.
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from typing import Annotated, AsyncGenerator, Optional

from fastapi import BackgroundTasks, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from logging_config import configure_logging, get_logger
from models import ExportRequest, ScreenshotCaptureResponse
from cache import screenshot_cache
from config import PORT_RISK
from resolver import resolve_target, is_ssrf_blocked
from scanner import scan_ports_stream, get_port_range, PROFILES
from auditor import run_full_audit
from ssl_analyzer import analyze_ssl_for_ports
from cve_lookup import lookup_cves, lookup_cves_for_ports, get_cache_stats
from scan_service import (
    fetch_geoip,
    ping_sweep,
    enumerate_subdomains,
    run_nmap,
    nmap_timeout,
    take_screenshot,
    build_markdown_report,
    set_browser,
    clear_browser,
)

import ipaddress
import re as _re

# ──────────────────────────────────────────────────────────────────────────────
# Lifespan  (startup + shutdown)
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:  # noqa: ARG001
    # ── Startup ───────────────────────────────────────────────────────────────
    configure_logging(os.getenv("LOG_LEVEL", "INFO"))
    logger.info(
        "lukitaport_starting",
        allow_private_ips=os.getenv("ALLOW_PRIVATE_IPS", "false"),
    )

    # ── Playwright shared browser ─────────────────────────────────────────────
    _pw = None
    _browser_instance = None

    try:
        from playwright.async_api import async_playwright  # type: ignore[import]
        _pw               = await async_playwright().start()
        _browser_instance = await _pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        set_browser(_browser_instance)
        logger.info("playwright_ready", browser="chromium")
    except ImportError:
        logger.warning(
            "playwright_not_installed",
            detail="Screenshots will fall back to per-request launch.",
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "playwright_launch_failed",
            error=str(exc),
            detail="Screenshots will fall back to per-request launch.",
        )

    # ── Background screenshot-cache eviction ──────────────────────────────────
    async def _evict_loop() -> None:
        while True:
            await asyncio.sleep(300)
            removed = screenshot_cache.evict_expired()
            if removed:
                logger.info("screenshot_cache_evicted", removed=removed)

    evict_task = asyncio.create_task(_evict_loop())

    # ── Hand off to the application ───────────────────────────────────────────
    yield

    # ── Shutdown ─────────────────────────────────────────────────────────────
    evict_task.cancel()

    clear_browser()

    if _browser_instance is not None:
        try:
            await _browser_instance.close()
            logger.info("playwright_browser_closed")
        except Exception as exc:  # noqa: BLE001
            logger.warning("playwright_browser_close_error", error=str(exc))

    if _pw is not None:
        try:
            await _pw.stop()
            logger.info("playwright_stopped")
        except Exception as exc:  # noqa: BLE001
            logger.warning("playwright_stop_error", error=str(exc))

    logger.info("lukitaport_shutdown")


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI application
# ──────────────────────────────────────────────────────────────────────────────

logger = get_logger(__name__)

app = FastAPI(
    title="LukitaPort",
    version="2.0.0",
    description=(
        "Async port scanner with real-time SSE streaming, HTTP security audit, "
        "SSL/TLS analysis, CVE lookup, network discovery, and subdomain enumeration."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="frontend"), name="static")


# ──────────────────────────────────────────────────────────────────────────────
# Input validation helpers
# ──────────────────────────────────────────────────────────────────────────────

_HOSTNAME_RE     = _re.compile(
    r"^(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)){0,126}$"
)
_DOMAIN_LABEL_RE = _re.compile(r"^[A-Za-z0-9\-]{1,63}$")


def _json_response(data: dict, status_code: int = 200) -> Response:
    return Response(
        content=json.dumps(data),
        status_code=status_code,
        media_type="application/json",
    )


def _bad(msg: str, status_code: int = 400) -> Response:
    return _json_response({"ok": False, "error": msg}, status_code)


def _ssrf_error(ip: str) -> Response:
    """
    Return HTTP 403 when a resolved IP is in a private/internal range.

    The body includes the offending IP so the client can show a helpful
    message.  Blocked IPs are also logged (warning level) by resolver.py.
    """
    return _json_response(
        {
            "ok":    False,
            "error": "ssrf_blocked",
            "detail": (
                f"Scanning internal addresses is not permitted (resolved: {ip}). "
                "Set ALLOW_PRIVATE_IPS=true to enable scanning private networks."
            ),
        },
        status_code=403,
    )


def _validate_target(target: str) -> tuple[Optional[str], Optional[Response]]:
    t = target.strip()
    if not t or len(t) > 253:
        return None, _bad("Invalid target: empty or exceeds 253 characters.")
    try:
        ipaddress.ip_address(t)
        return t, None
    except ValueError:
        pass
    if _HOSTNAME_RE.match(t) and "." in t:
        return t, None
    return None, _bad(f"Invalid target: '{t}' is not a valid IPv4, IPv6, or RFC 1123 hostname.")


def _validate_cidr(
    cidr: str,
) -> tuple[Optional[ipaddress.IPv4Network | ipaddress.IPv6Network], Optional[Response]]:
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False), None
    except ValueError as exc:
        return None, _bad(f"Invalid CIDR: {exc}")


def _validate_domain(domain: str) -> tuple[Optional[str], Optional[Response]]:
    d = domain.strip().lstrip("*.").lower()
    if not d or len(d) > 253 or "." not in d:
        return None, _bad("Invalid domain: must contain at least one dot.")
    labels = d.split(".")
    if not all(_DOMAIN_LABEL_RE.match(lbl) for lbl in labels):
        return None, _bad(f"Invalid domain: '{d}' contains invalid characters.")
    return d, None


def _validate_ports_str(ports: str) -> tuple[Optional[list[int]], Optional[Response]]:
    result: list[int] = []
    for p in ports.split(","):
        p = p.strip()
        if not p.isdigit():
            return None, _bad(f"Invalid port value: '{p}'")
        pint = int(p)
        if not (1 <= pint <= 65_535):
            return None, _bad(f"Port {pint} is out of range (1–65535).")
        result.append(pint)
    return result, None


def _check_resolution(resolution: dict) -> Optional[Response]:
    """
    Check the result of ``resolve_target()``.

    Returns an error Response (400 or 403) if:
    • DNS resolution failed, or
    • The resolved IP is an internal address and ALLOW_PRIVATE_IPS is false.

    Returns None on success — the caller may proceed.
    """
    if not resolution["ip"]:
        return _bad(f"Could not resolve target: {resolution['error']}")

    if resolution["error"] == "ssrf_blocked":
        return _ssrf_error(resolution["ip"])

    # Extra guard: re-check the IP directly (defence in depth for any code
    # path that calls resolve_target without the ssrf_blocked sentinel).
    if is_ssrf_blocked(resolution["ip"]):
        return _ssrf_error(resolution["ip"])

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Config / Root
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/config", include_in_schema=False)
def get_config() -> dict:
    return {"portRisk": {str(k): v for k, v in PORT_RISK.items()}}


@app.get("/", include_in_schema=False)
def root() -> FileResponse:
    return FileResponse("frontend/index.html")


# ──────────────────────────────────────────────────────────────────────────────
# Resolve
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/resolve")
async def resolve(target: str = Query(...)) -> Response:
    safe, err = _validate_target(target)
    if err:
        return err
    resolution = resolve_target(safe)
    # Expose ssrf_blocked as a 403 at this endpoint too, so the frontend
    # can surface a clear error message before the user even starts a scan.
    resolution_err = _check_resolution(resolution)
    if resolution_err:
        return resolution_err
    return _json_response(resolution)


# ──────────────────────────────────────────────────────────────────────────────
# GeoIP
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/geoip")
async def geoip(target: str = Query(...)) -> Response:
    safe, err = _validate_target(target)
    if err:
        return err
    resolution = resolve_target(safe)
    resolution_err = _check_resolution(resolution)
    if resolution_err:
        return resolution_err
    geo = await fetch_geoip(resolution["ip"])
    return _json_response({"ip": resolution["ip"], **geo})


# ──────────────────────────────────────────────────────────────────────────────
# Scan  (SSE streaming)
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/scan")
async def scan(
    request:    Request,
    target:     str   = Query(...),
    mode:       str   = Query("quick",  pattern=r"^(quick|full|custom)$"),
    profile:    str   = Query("normal", pattern=r"^(stealth|normal|aggressive)$"),
    port_start: int   = Query(1,    ge=1, le=65_535),
    port_end:   int   = Query(1024, ge=1, le=65_535),
    timeout:    float = Query(1.0,  ge=0.1, le=5.0),
) -> StreamingResponse:

    async def _error_stream(msg: str, status: int = 400) -> AsyncGenerator[str, None]:
        yield f"data: {json.dumps({'error': msg, 'status': status})}\n\n"

    safe, err = _validate_target(target)
    if err:
        return StreamingResponse(
            _error_stream("Invalid target."),
            media_type="text/event-stream",
        )

    resolution = resolve_target(safe)

    # SSRF check — propagate as an SSE error event so the frontend
    # receives a structured message even over the event stream.
    if not resolution["ip"]:
        return StreamingResponse(
            _error_stream(f"Could not resolve target: {resolution['error']}"),
            media_type="text/event-stream",
        )
    if resolution["error"] == "ssrf_blocked" or is_ssrf_blocked(resolution["ip"]):
        return StreamingResponse(
            _error_stream(
                f"Scanning internal addresses is not permitted "
                f"(resolved: {resolution['ip']}). "
                "Set ALLOW_PRIVATE_IPS=true to scan private networks.",
                status=403,
            ),
            media_type="text/event-stream",
        )

    ip    = resolution["ip"]
    ports = get_port_range(mode, port_start, port_end)
    prof  = PROFILES.get(profile, PROFILES["normal"])

    logger.info(
        "scan_start",
        target=safe,
        ip=ip,
        mode=mode,
        profile=profile,
        port_count=len(ports),
    )

    async def event_stream() -> AsyncGenerator[str, None]:
        try:
            geo = await asyncio.wait_for(
                asyncio.create_task(fetch_geoip(ip)), timeout=3.0
            )
        except Exception:
            geo = {}

        meta = {
            "type":        "meta",
            "ip":          ip,
            "hostname":    resolution["hostname"],
            "resolved":    resolution["resolved"],
            "total_ports": len(ports),
            "mode":        mode,
            "profile":     profile,
            "input":       target,
            "geo":         geo,
        }
        yield f"data: {json.dumps(meta)}\n\n"

        open_count = 0
        async for result in scan_ports_stream(
            ip, ports, timeout,
            max_concurrent=prof["max_concurrent"],
            inter_delay=prof["inter_delay"],
        ):
            if await request.is_disconnected():
                logger.info("scan_cancelled", ip=ip)
                yield f"data: {json.dumps({'type': 'cancelled'})}\n\n"
                return

            if result["state"] == "open":
                open_count += 1
            result["type"] = "port"
            yield f"data: {json.dumps(result)}\n\n"

        logger.info("scan_done", ip=ip, open=open_count, total=len(ports))
        yield (
            f"data: {json.dumps({'type': 'done', 'open_ports': open_count, 'total_scanned': len(ports)})}\n\n"
        )

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ──────────────────────────────────────────────────────────────────────────────
# Network Discovery
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/discover")
async def discover(
    cidr:      str = Query(..., description="CIDR range, e.g. 192.168.1.0/24"),
    max_hosts: int = Query(254, ge=1, le=1024),
) -> Response:
    network, err = _validate_cidr(cidr)
    if err:
        return err
    hosts = list(network.hosts())[:max_hosts]
    if not hosts:
        return _json_response({"error": "No hosts in range", "alive": []})

    alive = await ping_sweep(hosts)
    return _json_response({
        "cidr":        cidr,
        "total_hosts": len(hosts),
        "alive_count": len(alive),
        "alive":       alive,
    })


# ──────────────────────────────────────────────────────────────────────────────
# Subdomain Enumeration
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/subdomains")
async def subdomains(domain: str = Query(...)) -> Response:
    safe, err = _validate_domain(domain)
    if err:
        return err
    result = await enumerate_subdomains(safe)
    return _json_response(result)


# ──────────────────────────────────────────────────────────────────────────────
# Fingerprint (nmap -sV)
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/fingerprint")
async def fingerprint(
    request: Request,  # reserved for future per-request cancellation
    target:  str = Query(...),
    ports:   str = Query(...),
) -> Response:
    safe, err = _validate_target(target)
    if err:
        return err
    port_list, err2 = _validate_ports_str(ports)
    if err2:
        return err2

    resolution = resolve_target(safe)
    resolution_err = _check_resolution(resolution)
    if resolution_err:
        return resolution_err

    ports_str   = ",".join(str(p) for p in port_list)
    timeout_sec = nmap_timeout(len(port_list))
    results     = await run_nmap(resolution["ip"], ports_str, timeout_sec)

    return _json_response({
        "ip":          resolution["ip"],
        "timeout_sec": timeout_sec,
        "results":     results,
    })


# ──────────────────────────────────────────────────────────────────────────────
# Screenshot
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/screenshot")
async def get_screenshot(target: str = Query(...)) -> Response:
    data = screenshot_cache.get(target)
    if not data:
        return Response(status_code=204)
    return Response(
        content=data["png"],
        media_type="image/png",
        headers={"X-Screenshot-Url": data.get("url", "")},
    )


@app.post("/api/screenshot/capture")
async def capture_screenshot(
    background_tasks: BackgroundTasks,
    target: str = Query(...),
    port:   int = Query(80, ge=1, le=65_535),
) -> Response:
    safe, err = _validate_target(target)
    if err:
        return err

    resolution = resolve_target(safe)
    resolution_err = _check_resolution(resolution)
    if resolution_err:
        return resolution_err

    hostname = resolution["hostname"] or target
    background_tasks.add_task(take_screenshot, hostname, port)

    payload = ScreenshotCaptureResponse(status="capturing", target=hostname, port=port)
    return _json_response(payload.model_dump())


@app.get("/api/screenshot/cache-stats", include_in_schema=False)
async def screenshot_cache_stats() -> Response:
    return _json_response(screenshot_cache.stats())


# ──────────────────────────────────────────────────────────────────────────────
# Audit
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/audit")
async def audit(
    target:     str = Query(...),
    open_ports: str = Query("80,443"),
) -> Response:
    safe, err = _validate_target(target)
    if err:
        return err
    port_list, err2 = _validate_ports_str(open_ports)
    if err2:
        return err2

    resolution = resolve_target(safe)
    resolution_err = _check_resolution(resolution)
    if resolution_err:
        return resolution_err

    hostname = resolution["hostname"] or target
    result   = await run_full_audit(hostname, port_list)
    return _json_response({"target": target, "ip": resolution["ip"], **result})


# ──────────────────────────────────────────────────────────────────────────────
# SSL Analysis
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/ssl")
async def ssl_analysis(
    target:     str   = Query(...),
    open_ports: str   = Query("443"),
    timeout:    float = Query(8.0, ge=1.0, le=30.0),
) -> Response:
    safe, err = _validate_target(target)
    if err:
        return err
    port_list, err2 = _validate_ports_str(open_ports)
    if err2:
        return err2

    resolution = resolve_target(safe)
    resolution_err = _check_resolution(resolution)
    if resolution_err:
        return resolution_err

    hostname = resolution["hostname"] or target
    loop     = asyncio.get_event_loop()
    result   = await loop.run_in_executor(
        None, analyze_ssl_for_ports, hostname, port_list, timeout
    )
    return _json_response({"target": target, "ip": resolution["ip"], **result})


# ──────────────────────────────────────────────────────────────────────────────
# CVE lookup
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/cve")
async def cve_lookup_endpoint(
    service:     str = Query(...),
    version:     str = Query(""),
    max_results: int = Query(5, ge=1, le=10),
) -> Response:
    result = await lookup_cves(service, version, max_results)
    return _json_response(result)


@app.post("/api/cve/batch")
async def cve_batch(versions: dict) -> Response:
    results = await lookup_cves_for_ports(versions)
    return _json_response({"results": results})


@app.get("/api/cve/cache-stats", include_in_schema=False)
async def cve_cache_stats() -> Response:
    return _json_response(get_cache_stats())


# ──────────────────────────────────────────────────────────────────────────────
# Markdown export
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/api/export/md")
async def export_markdown(payload: ExportRequest) -> Response:
    md = build_markdown_report(
        meta=payload.scan.meta,
        results=payload.scan.results,
        summary=payload.scan.summary,
        audit=payload.audit,
    )
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=lukitaport_report.md"},
    )


# ──────────────────────────────────────────────────────────────────────────────
# PDF export
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/api/export/pdf")
async def export_pdf(payload: ExportRequest) -> Response:
    try:
        from pdf_generator import generate_pdf  # type: ignore[import]

        screenshot_png: Optional[bytes] = None
        if payload.screenshot_target:
            sc = screenshot_cache.get(payload.screenshot_target)
            if sc:
                screenshot_png = sc.get("png")

        loop      = asyncio.get_event_loop()
        pdf_bytes = await loop.run_in_executor(
            None,
            generate_pdf,
            {
                "meta":    payload.scan.meta,
                "results": payload.scan.results,
                "summary": payload.scan.summary,
            },
            payload.audit,
            screenshot_png,
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=lukitaport_report.pdf"},
        )
    except ImportError:
        return _json_response({"error": "reportlab not installed."}, 500)
    except Exception as exc:  # noqa: BLE001
        logger.error("pdf_export_error", error=str(exc))
        return _json_response({"error": str(exc)}, 500)


# ──────────────────────────────────────────────────────────────────────────────
# Admin / dev helpers
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/api/admin/reload-signatures", include_in_schema=False)
async def reload_tech_signatures() -> Response:
    """Hot-reload technology detection signatures from tech_signatures.json."""
    from auditor import reload_signatures
    count = reload_signatures()
    return _json_response({"ok": True, "signatures_loaded": count})


@app.get("/api/admin/status", include_in_schema=False)
async def server_status() -> Response:
    """Health / status endpoint for monitoring."""
    from scan_service import _browser as pw_browser
    return _json_response({
        "ok":                 True,
        "playwright_ready":   pw_browser is not None,
        "screenshot_cache":   screenshot_cache.stats(),
        "allow_private_ips":  os.getenv("ALLOW_PRIVATE_IPS", "false"),
    })
