"""
main.py
───────
LukitaPort — FastAPI application entry point.

Route handlers are intentionally thin:
  1. Inputs are validated by the types in models.py (HTTP 422 on failure).
  2. Work is delegated to the service modules.
  3. JSON responses are typed with ``response_model``.

Errors
──────
Every error response has the same shape (``models.ErrorResponse``)::

    {"ok": false, "error": "<code>", "detail": "<message>"}

Handlers raise ``ApiError(status, code, detail)``; the exception handlers
below also map validation errors (422), unknown routes (404), busy limits
(429) and unexpected exceptions (500, details only in the log) to it.

Lifespan
────────
Startup: validate configuration (fail fast), configure logging, launch a
shared Chromium if Playwright is available, start the screenshot-cache
eviction task.  Shutdown: stop the task and close the browser.

Access control
──────────────
``security.SecurityMiddleware`` requires the API token on every ``/api/``
route (except auth and health), validates the Host header, adds security
headers (CSP, …), rate-limits clients and caps request bodies.

SSRF protection
───────────────
Every target is resolved once; if *any* address is internal the request gets
HTTP 403 (unless ``ALLOW_PRIVATE_IPS=true``).  The first address is pinned
and every later connection for that request goes to it.

Resource limits
───────────────
Heavy operations take a slot from ``limits``; when none is free the request
fails fast with HTTP 429.
"""

from __future__ import annotations

import asyncio
import ipaddress
import itertools
import json
from collections.abc import AsyncGenerator
from contextlib import aclosing, asynccontextmanager
from typing import Annotated, Any, Optional

from fastapi import BackgroundTasks, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

import geoip as geoip_db   # (module; `geoip` is also an endpoint below)
import limits
import security
import settings as app_settings
from auditor import run_full_audit
from cache import screenshot_cache
from config import PORT_RISK
from cve_lookup import get_cache_stats, lookup_cves, lookup_cves_for_ports
from logging_config import configure_logging, get_logger
from models import (
    AuditResponse,
    AuthRequest,
    AuthStatus,
    CVEBatchRequest,
    CVEBatchResponse,
    CVELookupResponse,
    DiscoverCidr,
    DiscoverResponse,
    DomainStr,
    ErrorResponse,
    ExportRequest,
    FingerprintResponse,
    GeoIPResponse,
    HealthResponse,
    ResolveResponse,
    ScreenshotCaptureResponse,
    SSLResponse,
    SubdomainsResponse,
    TargetStr,
    parse_ports,
    validate_target,
)
from resolver import is_ssrf_blocked, network_ssrf_blocked, resolve_target
from scan_service import (
    BROWSER_ARGS,
    NMAP_TIMEOUT_BASE,
    NMAP_TIMEOUT_PER_PORT,
    build_markdown_report,
    clear_browser,
    enumerate_subdomains,
    fetch_geoip,
    nmap_timeout,
    ping_sweep,
    run_nmap,
    screenshots_supported,
    set_browser,
    take_screenshot,
)
from scanner import PROFILES, ScanResourceError, get_port_range, scan_ports_stream
from ssl_analyzer import analyze_ssl_for_ports

logger = get_logger(__name__)

# Seconds between client-disconnect checks while streaming scan results.
DISCONNECT_CHECK_INTERVAL = 0.5


# ──────────────────────────────────────────────────────────────────────────────
# Errors
# ──────────────────────────────────────────────────────────────────────────────

class ApiError(Exception):
    """An error returned to the client in the common error format."""

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code   = code
        self.detail = detail


def _error_json(status: int, code: str, detail: str, **extra: Any) -> JSONResponse:
    body = ErrorResponse(error=code, detail=detail, **extra)
    return JSONResponse(body.model_dump(exclude_none=True), status_code=status)


def _ssrf_detail(ip: str) -> str:
    return (
        f"Scanning internal addresses is not permitted (resolved: {ip}). "
        "Set ALLOW_PRIVATE_IPS=true to enable scanning private networks."
    )


# Documented on every JSON endpoint (OpenAPI).
_ERRORS: dict[int | str, dict[str, Any]] = {
    code: {"model": ErrorResponse} for code in (400, 401, 403, 422, 429, 500)
}


# ──────────────────────────────────────────────────────────────────────────────
# Lifespan  (startup + shutdown)
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # ── Startup ───────────────────────────────────────────────────────────────
    # Fail fast on an invalid or unsafe configuration.
    cfg = app_settings.get_settings()
    configure_logging(cfg.log_level)
    sec = security.get_settings()
    logger.info(
        "lukitaport_starting",
        allow_private_ips=cfg.allow_private_ips,
        token_source="env" if sec.token_from_env else "generated",
        admin_enabled=sec.enable_admin,
        geoip=geoip_db.status()["enabled"],
    )
    if not sec.token_from_env:
        # Ephemeral token: show the operator how to log in.  The token is in
        # the URL fragment, which browsers never send to the server.
        url = security.login_url(sec, cfg.port)
        logger.warning("api_token_generated", login_url=url)
        print(f"\n  LukitaPort — open this URL to log in:\n  {url}\n", flush=True)

    # ── Playwright shared browser (optional) ──────────────────────────────────
    pw = None
    browser = None
    try:
        from playwright.async_api import async_playwright
        pw      = await async_playwright().start()
        browser = await pw.chromium.launch(headless=True, args=BROWSER_ARGS)
        set_browser(browser)
        logger.info("playwright_ready", browser="chromium")
    except ImportError:
        logger.warning("playwright_not_installed", detail="Screenshots are disabled.")
    except Exception as exc:
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

    yield

    # ── Shutdown ─────────────────────────────────────────────────────────────
    evict_task.cancel()
    clear_browser()
    if browser is not None:
        try:
            await browser.close()
            logger.info("playwright_browser_closed")
        except Exception as exc:
            logger.warning("playwright_browser_close_error", error=str(exc))
    if pw is not None:
        try:
            await pw.stop()
            logger.info("playwright_stopped")
        except Exception as exc:
            logger.warning("playwright_stop_error", error=str(exc))
    logger.info("lukitaport_shutdown")


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI application
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="LukitaPort",
    version="2.1.0",
    description=(
        "Async port scanner with real-time SSE streaming, HTTP security audit, "
        "SSL/TLS analysis, CVE lookup, network discovery, and subdomain enumeration. "
        "For authorised, educational use only."
    ),
    lifespan=lifespan,
    # Swagger UI / ReDoc load scripts from a CDN, which the CSP forbids; the
    # schema itself stays available at /openapi.json.
    docs_url=None,
    redoc_url=None,
)

# No CORS: the UI is served from the same origin and no other site may call
# the API.  SecurityMiddleware handles auth, Host checks, headers and limits.
app.add_middleware(security.SecurityMiddleware)
app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.exception_handler(ApiError)
async def _api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return _error_json(exc.status, exc.code, exc.detail)


@app.exception_handler(limits.Busy)
async def _busy_handler(request: Request, exc: limits.Busy) -> JSONResponse:
    return _error_json(429, "busy", str(exc))


@app.exception_handler(RequestValidationError)
async def _validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [
        {"loc": list(e.get("loc", ())), "msg": str(e.get("msg", "")), "type": e.get("type", "")}
        for e in exc.errors()
    ]
    first_loc: list = errors[0]["loc"] if errors else []
    first_msg: str  = errors[0]["msg"] if errors else "Invalid request"
    where  = ".".join(str(p) for p in first_loc if p not in ("query", "body"))
    detail = f"{where}: {first_msg}" if where else first_msg
    return _error_json(422, "validation_error", detail, errors=errors)


@app.exception_handler(StarletteHTTPException)
async def _http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
    return _error_json(exc.status_code, code, str(exc.detail))


@app.exception_handler(Exception)
async def _unexpected_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("unhandled_error", path=request.url.path, error=str(exc), exc_info=exc)
    return _error_json(500, "internal_error", "Internal server error.")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _ports(raw: str, max_ports: int) -> list[int]:
    try:
        return parse_ports(raw, max_ports)
    except ValueError as exc:
        raise ApiError(422, "validation_error", f"ports: {exc}") from exc


async def _resolve_checked(target: str, reverse_dns: bool = False) -> dict:
    """
    Resolve ``target`` and enforce the SSRF policy.

    Raises ``ApiError`` 400 when it does not resolve and 403 when any of its
    addresses is internal (and private addresses are not allowed).
    """
    resolution = await resolve_target(target, reverse_dns=reverse_dns)
    if not resolution["ip"]:
        raise ApiError(400, "unresolvable", f"Could not resolve target: {resolution['error']}")
    # Second check is defence in depth for the ssrf_blocked sentinel.
    if resolution["error"] == "ssrf_blocked" or is_ssrf_blocked(resolution["ip"]):
        raise ApiError(403, "ssrf_blocked", _ssrf_detail(resolution["ip"]))
    return resolution


# ──────────────────────────────────────────────────────────────────────────────
# Health / config / UI
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/health", response_model=HealthResponse, include_in_schema=False)
def health() -> dict:
    """Liveness probe (no authentication, no details)."""
    return {"ok": True}


@app.get("/api/config", include_in_schema=False)
def get_config() -> dict:
    return {
        "portRisk": {str(k): v for k, v in PORT_RISK.items()},
        "geoip":    geoip_db.status(),
        "nmap":     {"timeoutBase": NMAP_TIMEOUT_BASE, "timeoutPerPort": NMAP_TIMEOUT_PER_PORT},
        "limits":   {"cveBatch": limits.MAX_CVE_BATCH, "fingerprintPorts": limits.MAX_FINGERPRINT_PORTS},
    }


@app.get("/", include_in_schema=False)
def root() -> FileResponse:
    return FileResponse("frontend/index.html")


# ──────────────────────────────────────────────────────────────────────────────
# Authentication  (exempt from the token check, see security.py)
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/auth/status", response_model=AuthStatus, include_in_schema=False)
def auth_status(request: Request) -> dict:
    headers = {k.lower(): v for k, v in request.headers.items()}
    return {"authenticated": security.is_authenticated(headers, security.get_settings())}


@app.post("/api/auth", status_code=204, responses=_ERRORS, include_in_schema=False)
def auth_login(payload: AuthRequest, request: Request) -> Response:
    sec = security.get_settings()
    if not sec.token_matches(payload.token):
        logger.warning("auth_failed", client=request.client.host if request.client else None)
        raise ApiError(401, "invalid_token", "Invalid token.")
    resp = Response(status_code=204)
    resp.set_cookie(
        security.SESSION_COOKIE,
        sec.session_value(),
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return resp


@app.post("/api/auth/logout", status_code=204, include_in_schema=False)
def auth_logout() -> Response:
    resp = Response(status_code=204)
    resp.delete_cookie(security.SESSION_COOKIE, path="/")
    return resp


# ──────────────────────────────────────────────────────────────────────────────
# Resolve / GeoIP
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/resolve", response_model=ResolveResponse, responses=_ERRORS)
async def resolve(target: Annotated[TargetStr, Query()]) -> dict:
    return await _resolve_checked(target, reverse_dns=True)


@app.get("/api/geoip", response_model=GeoIPResponse, response_model_exclude_none=True,
         responses=_ERRORS)
async def geoip(target: Annotated[TargetStr, Query()]) -> dict:
    resolution = await _resolve_checked(target)
    if not geoip_db.is_enabled():
        return {"ip": resolution["ip"], "enabled": False}
    return {"ip": resolution["ip"], "enabled": True, **await fetch_geoip(resolution["ip"])}


# ──────────────────────────────────────────────────────────────────────────────
# Scan  (SSE streaming)
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/scan", response_class=StreamingResponse)
async def scan(
    request:    Request,
    target:     Annotated[str, Query(max_length=300)],
    mode:       Annotated[str, Query(pattern=r"^(quick|full|custom)$")] = "quick",
    profile:    Annotated[str, Query(pattern=r"^(stealth|normal|aggressive|slow)$")] = "normal",
    port_start: Annotated[int, Query(ge=1, le=65_535)] = 1,
    port_end:   Annotated[int, Query(ge=1, le=65_535)] = 1024,
    timeout:    Annotated[float, Query(ge=0.1, le=5.0)] = 1.0,
) -> StreamingResponse:
    """
    Stream results as Server-Sent Events.  Errors that happen before the
    stream starts are also sent as one SSE event
    (``{"error": ..., "status": ...}``) so EventSource clients can show them.
    """

    def _error_stream(msg: str, status: int) -> StreamingResponse:
        async def stream() -> AsyncGenerator[str, None]:
            yield f"data: {json.dumps({'error': msg, 'status': status})}\n\n"
        return StreamingResponse(stream(), media_type="text/event-stream")

    try:
        safe = validate_target(target)
    except ValueError as exc:
        return _error_stream(f"Invalid target: {exc}", 422)
    if mode == "custom" and port_start > port_end:
        return _error_stream(
            f"Invalid custom range: start port ({port_start}) is greater than end port ({port_end}).",
            422,
        )
    try:
        resolution = await _resolve_checked(safe, reverse_dns=True)
    except ApiError as exc:
        return _error_stream(exc.detail, exc.status)

    ip    = resolution["ip"]
    ports = get_port_range(mode, port_start, port_end)
    prof  = PROFILES[profile]

    logger.info("scan_start", target=safe, ip=ip, mode=mode, profile=profile, port_count=len(ports))

    async def event_stream() -> AsyncGenerator[str, None]:
        # The slot is taken inside the generator so it is released in the
        # same place (finally) even if the client disconnects early.
        if not limits.scans.try_acquire():
            yield f"data: {json.dumps({'error': str(limits.Busy('scan')), 'status': 429})}\n\n"
            return
        try:
            async with aclosing(_scan_events()) as events:
                async for chunk in events:
                    yield chunk
        finally:
            limits.scans.release()

    async def _scan_events() -> AsyncGenerator[str, None]:
        try:
            geo = await asyncio.wait_for(fetch_geoip(ip), timeout=3.0)
        except Exception:
            geo = {}

        meta = {
            "type":        "meta",
            "ip":          ip,
            "hostname":    resolution["hostname"],
            "ptr":         resolution.get("ptr"),
            "resolved":    resolution["resolved"],
            "total_ports": len(ports),
            "mode":        mode,
            "profile":     profile,
            "input":       target,
            "geo":         geo,
        }
        yield f"data: {json.dumps(meta)}\n\n"

        open_count = 0
        loop = asyncio.get_running_loop()
        next_disconnect_check = loop.time() + DISCONNECT_CHECK_INTERVAL
        # aclosing: whatever ends this loop (disconnect, error, cancellation)
        # closes the scanner generator, which cancels its worker tasks.
        async with aclosing(scan_ports_stream(
            ip, ports, timeout,
            max_concurrent=prof["max_concurrent"],
            inter_delay=prof["inter_delay"],
            jitter=prof["jitter"],
            shuffle=prof["shuffle"],
        )) as results:
            try:
                async for result in results:
                    # Polling is_disconnected() per port is costly on full
                    # scans; once per interval is enough.
                    if loop.time() >= next_disconnect_check:
                        next_disconnect_check = loop.time() + DISCONNECT_CHECK_INTERVAL
                        if await request.is_disconnected():
                            logger.info("scan_cancelled", ip=ip)
                            yield f"data: {json.dumps({'type': 'cancelled'})}\n\n"
                            return

                    if result["state"] == "open":
                        open_count += 1
                    result["type"] = "port"
                    yield f"data: {json.dumps(result)}\n\n"
            except ScanResourceError as exc:
                logger.error("scan_resource_error", ip=ip, error=str(exc))
                yield f"data: {json.dumps({'error': str(exc), 'status': 503})}\n\n"
                return

        logger.info("scan_done", ip=ip, open=open_count, total=len(ports))
        done = {"type": "done", "open_ports": open_count, "total_scanned": len(ports)}
        yield f"data: {json.dumps(done)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ──────────────────────────────────────────────────────────────────────────────
# Network Discovery
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/discover", response_model=DiscoverResponse, responses=_ERRORS)
async def discover(
    cidr:      Annotated[DiscoverCidr, Query(description="IPv4 CIDR, /22 or narrower")],
    max_hosts: Annotated[int, Query(ge=1, le=1024)] = 254,
) -> dict:
    network = ipaddress.IPv4Network(cidr)
    if network_ssrf_blocked(network):
        raise ApiError(403, "ssrf_blocked", _ssrf_detail(str(network)))
    # islice: never materialise more host objects than will be pinged.
    hosts = list(itertools.islice(network.hosts(), max_hosts))
    alive = await ping_sweep(hosts)
    return {"cidr": cidr, "total_hosts": len(hosts), "alive_count": len(alive), "alive": alive}


# ──────────────────────────────────────────────────────────────────────────────
# Subdomain Enumeration
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/subdomains", response_model=SubdomainsResponse,
         responses={**_ERRORS, 502: {"model": ErrorResponse}})
async def subdomains(domain: Annotated[DomainStr, Query()]) -> dict:
    result = await enumerate_subdomains(domain)
    if result.get("error"):
        raise ApiError(502, "upstream_error", result["error"])
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Fingerprint (nmap -sV)
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/fingerprint", response_model=FingerprintResponse, responses=_ERRORS)
async def fingerprint(
    target: Annotated[TargetStr, Query()],
    ports:  Annotated[str, Query(max_length=1000)],
) -> dict:
    port_list  = _ports(ports, limits.MAX_FINGERPRINT_PORTS)
    resolution = await _resolve_checked(target)

    ports_str   = ",".join(str(p) for p in port_list)
    timeout_sec = nmap_timeout(len(port_list))
    async with limits.nmap:
        results = await run_nmap(resolution["ip"], ports_str, timeout_sec)

    return {
        "ip":          resolution["ip"],
        "timeout_sec": timeout_sec,
        "results":     {str(k): v for k, v in results.items()},
    }


# ──────────────────────────────────────────────────────────────────────────────
# Screenshot
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/screenshot", responses={200: {"content": {"image/png": {}}}, 204: {}})
async def get_screenshot(target: Annotated[str, Query(max_length=300)]) -> Response:
    data = screenshot_cache.get(target)
    if not data:
        return Response(status_code=204)
    return Response(
        content=data["png"],
        media_type="image/png",
        headers={"X-Screenshot-Url": data.get("url", "")},
    )


@app.post("/api/screenshot/capture", response_model=ScreenshotCaptureResponse,
          responses={**_ERRORS, 503: {"model": ErrorResponse}})
async def capture_screenshot(
    background_tasks: BackgroundTasks,
    target: Annotated[TargetStr, Query()],
    port:   Annotated[int, Query(ge=1, le=65_535)] = 80,
) -> dict:
    if not screenshots_supported():
        raise ApiError(503, "screenshots_unavailable",
                       "Screenshots are not available (Playwright is not installed).")
    resolution = await _resolve_checked(target)
    hostname   = resolution["hostname"] or resolution["ip"]
    # The slot is released by take_screenshot when the capture finishes.
    limits.screenshots.acquire()
    background_tasks.add_task(take_screenshot, hostname, resolution["ip"], port)
    return {"status": "capturing", "target": hostname, "port": port}


@app.get("/api/screenshot/cache-stats", include_in_schema=False)
async def screenshot_cache_stats() -> dict:
    return screenshot_cache.stats()


# ──────────────────────────────────────────────────────────────────────────────
# Audit / SSL
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/audit", response_model=AuditResponse, responses=_ERRORS)
async def audit(
    target:     Annotated[TargetStr, Query()],
    open_ports: Annotated[str, Query(max_length=6000)] = "80,443",
) -> dict:
    port_list  = _ports(open_ports, limits.MAX_AUDIT_PORTS)
    resolution = await _resolve_checked(target)
    hostname   = resolution["hostname"] or resolution["ip"]
    async with limits.audits:
        result = await run_full_audit(hostname, port_list, pinned_ip=resolution["ip"])
    return {"target": target, "ip": resolution["ip"], **result}


@app.get("/api/ssl", response_model=SSLResponse, responses=_ERRORS)
async def ssl_analysis(
    target:     Annotated[TargetStr, Query()],
    open_ports: Annotated[str, Query(max_length=6000)] = "443",
    timeout:    Annotated[float, Query(ge=1.0, le=30.0)] = 8.0,
) -> dict:
    port_list  = _ports(open_ports, limits.MAX_AUDIT_PORTS)
    resolution = await _resolve_checked(target)
    hostname   = resolution["hostname"] or resolution["ip"]
    loop       = asyncio.get_running_loop()
    async with limits.ssl_checks:
        result = await loop.run_in_executor(
            None, analyze_ssl_for_ports, hostname, port_list, timeout, resolution["ip"],
        )
    return {"target": target, "ip": resolution["ip"], **result}


# ──────────────────────────────────────────────────────────────────────────────
# CVE lookup
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/cve", response_model=CVELookupResponse, responses=_ERRORS)
async def cve_lookup_endpoint(
    service:     Annotated[str, Query(min_length=1, max_length=100)],
    version:     Annotated[str, Query(max_length=100)] = "",
    max_results: Annotated[int, Query(ge=1, le=10)] = 5,
    cpe:         Annotated[str, Query(max_length=200)] = "",
) -> dict:
    return await lookup_cves(service, version, max_results, cpe=cpe or None)


@app.post("/api/cve/batch", response_model=CVEBatchResponse, responses=_ERRORS)
async def cve_batch(versions: CVEBatchRequest) -> dict:
    payload = {port: info.model_dump() for port, info in versions.root.items()}
    return {"results": await lookup_cves_for_ports(payload)}


@app.get("/api/cve/cache-stats", include_in_schema=False)
async def cve_cache_stats() -> dict:
    return get_cache_stats()


# ──────────────────────────────────────────────────────────────────────────────
# Exports
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/api/export/md", responses={**_ERRORS, 200: {"content": {"text/markdown": {}}}})
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


@app.post("/api/export/pdf", responses={**_ERRORS, 200: {"content": {"application/pdf": {}}}})
async def export_pdf(payload: ExportRequest) -> Response:
    import pdf_generator   # heavy (ReportLab); imported on first use

    screenshot_png: Optional[bytes] = None
    if payload.screenshot_target:
        sc = screenshot_cache.get(payload.screenshot_target)
        if sc:
            screenshot_png = sc.get("png")

    loop = asyncio.get_running_loop()
    try:
        pdf_bytes = await loop.run_in_executor(
            None,
            pdf_generator.generate_pdf,
            {"meta": payload.scan.meta, "results": payload.scan.results, "summary": payload.scan.summary},
            payload.audit,
            screenshot_png,
        )
    except Exception as exc:
        logger.error("pdf_export_error", error=str(exc), exc_info=True)
        raise ApiError(500, "pdf_failed", "PDF generation failed.") from exc
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=lukitaport_report.pdf"},
    )


# ──────────────────────────────────────────────────────────────────────────────
# Admin (only when LUKITA_ENABLE_ADMIN=true, see security.py)
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/api/admin/reload-signatures", include_in_schema=False)
async def reload_tech_signatures() -> dict:
    """Hot-reload technology detection signatures from tech_signatures.json."""
    from auditor import reload_signatures
    return {"ok": True, "signatures_loaded": reload_signatures()}


@app.get("/api/admin/status", include_in_schema=False)
async def server_status() -> dict:
    import scan_service
    return {
        "ok":                True,
        "playwright_ready":  scan_service.browser_ready(),
        "screenshot_cache":  screenshot_cache.stats(),
        "limits":            limits.stats(),
        "allow_private_ips": app_settings.get_settings().allow_private_ips,
    }
