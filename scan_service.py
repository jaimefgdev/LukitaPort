"""
scan_service.py
───────────────
Service layer for LukitaPort.

All heavy business logic previously scattered through ``main.py`` lives here.
FastAPI route handlers are thin wrappers that call these functions and return
typed responses.

Responsibilities
────────────────
• GeoIP enrichment (local GeoLite2 only, off by default)
• Network discovery (ping sweep) with proper subprocess lifecycle
• Subdomain enumeration via crt.sh
• nmap fingerprinting with graceful CancelledError propagation
• Playwright screenshots — reuses a shared global browser instance
  (set by main.py lifespan via ``set_browser`` / ``clear_browser``)
• Markdown report building
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
import socket
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import TYPE_CHECKING, Optional

import httpx

import geoip
import limits
import safe_http
from cache import screenshot_cache
from config import port_risk
from logging_config import get_logger

if TYPE_CHECKING:
    # Avoid a hard import of playwright at module level; it may not be installed.
    from playwright.async_api import Browser

logger = get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Global Playwright browser handle
# ──────────────────────────────────────────────────────────────────────────────
# The lifespan in main.py calls set_browser() / clear_browser().
# take_screenshot() uses the shared instance so that Chromium only starts once
# per server process instead of once per screenshot request.
# ──────────────────────────────────────────────────────────────────────────────

_browser: Optional[Browser] = None


def set_browser(browser: Browser) -> None:
    """
    Register a live Playwright ``Browser`` instance.

    Called by the FastAPI lifespan handler immediately after launching
    Chromium.  Must be called before any ``take_screenshot`` invocations.
    """
    global _browser
    _browser = browser
    logger.info("playwright_browser_registered")


def browser_ready() -> bool:
    return _browser is not None


def screenshots_supported() -> bool:
    """True when Playwright is installed (the lite Docker image omits it)."""
    import importlib.util
    return _browser is not None or importlib.util.find_spec("playwright") is not None


def clear_browser() -> None:
    """
    Deregister the browser handle (called during lifespan shutdown).

    Does not close the browser — that is the lifespan's responsibility.
    """
    global _browser
    _browser = None
    logger.info("playwright_browser_cleared")


# ──────────────────────────────────────────────────────────────────────────────
# GeoIP
# ──────────────────────────────────────────────────────────────────────────────

async def fetch_geoip(ip: str) -> dict:
    """
    Return GeoIP data for ``ip`` from the local GeoLite2 database, or ``{}``
    when GeoIP is disabled (the default).  Never raises and never sends the
    address to a third party — see geoip.py.
    """
    if not geoip.is_enabled():
        return {}
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, geoip.lookup, ip)


# ──────────────────────────────────────────────────────────────────────────────
# Ping sweep / network discovery
# ──────────────────────────────────────────────────────────────────────────────

_IS_WINDOWS = sys.platform == "win32"


_TERMINATE_GRACE = 2.0


async def _terminate(proc: asyncio.subprocess.Process, grace: float = _TERMINATE_GRACE) -> None:
    """
    Stop ``proc`` and reap it: SIGTERM, wait up to ``grace`` seconds, then
    SIGKILL and wait.  Waiting is what prevents zombie processes.  Safe to
    call on a process that already exited.
    """
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(proc.wait(), grace)
        return
    except TimeoutError:
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    await proc.wait()


async def _cleanup_after_cancel(proc: Optional[asyncio.subprocess.Process]) -> None:
    """Reap ``proc`` even though the current task is being cancelled."""
    if proc is not None:
        await asyncio.shield(_terminate(proc))


async def _ping_one(ip_str: str) -> Optional[dict]:
    """
    Ping a single IP address.

    The subprocess is always reaped (timeout, error or cancellation) and
    ``CancelledError`` is re-raised so callers can actually cancel a sweep.
    Returns None when the host is unreachable.
    """
    args = (
        ["ping", "-n", "1", "-w", "800", ip_str]
        if _IS_WINDOWS
        else ["ping", "-c", "1", "-W", "1", ip_str]
    )

    proc: Optional[asyncio.subprocess.Process] = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
        except TimeoutError:
            await _terminate(proc)
            return None
    except asyncio.CancelledError:
        await _cleanup_after_cancel(proc)
        raise
    except OSError as exc:
        logger.debug("ping_error", ip=ip_str, error=str(exc))
        if proc is not None:
            await _terminate(proc)
        return None

    if proc.returncode == 0:
        output = stdout.decode("utf-8", errors="replace")
        rtt: Optional[float] = None
        for pattern in (r"time[<=](\d+\.?\d*)\s*ms", r"Average\s*=\s*(\d+)ms"):
            m = re.search(pattern, output, re.IGNORECASE)
            if m:
                rtt = float(m.group(1))
                break
        return {"ip": ip_str, "alive": True, "rtt_ms": rtt}
    return None


async def ping_sweep(hosts: list, concurrency: int = 64) -> list[dict]:
    """
    Ping all hosts concurrently (max ``concurrency`` at once).

    Returns a list of alive-host dicts sorted ascending by IP address.
    """
    sem = asyncio.Semaphore(concurrency)

    async def bounded(ip_obj) -> Optional[dict]:
        async with sem:
            return await _ping_one(str(ip_obj))

    tasks   = [asyncio.create_task(bounded(h)) for h in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    alive   = [
        r for r in results
        if isinstance(r, dict) and r and r.get("alive")
    ]
    alive.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    return alive


# ──────────────────────────────────────────────────────────────────────────────
# Subdomain enumeration (crt.sh)
# ──────────────────────────────────────────────────────────────────────────────

async def enumerate_subdomains(domain: str) -> dict:
    """Query crt.sh certificate transparency logs for subdomains of ``domain``."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return {"error": f"crt.sh returned {resp.status_code}", "subdomains": []}
            data = resp.json()
    except Exception as exc:
        return {"error": f"crt.sh unreachable: {exc}", "subdomains": []}

    seen:    set[str]   = set()
    results: list[dict] = []

    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.").lower()
            if not name or name in seen:
                continue
            if not (name == domain or name.endswith(f".{domain}")):
                continue
            if "*" in name:
                continue
            seen.add(name)
            results.append({
                "subdomain":  name,
                "issuer":     entry.get("issuer_name", ""),
                "not_before": entry.get("not_before", "")[:10],
                "not_after":  entry.get("not_after",  "")[:10],
            })

    results.sort(key=lambda x: x["subdomain"])

    async def resolve_sub(item: dict) -> dict:
        loop = asyncio.get_running_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, item["subdomain"])
            return {**item, "ip": ip, "resolves": True}
        except Exception:
            return {**item, "ip": None, "resolves": False}

    top  = results[:50]
    rest = results[50:]
    resolved = await asyncio.gather(
        *[asyncio.create_task(resolve_sub(r)) for r in top],
        return_exceptions=True,
    )
    resolved_list = [r for r in resolved if isinstance(r, dict)]
    for item in rest:
        resolved_list.append({**item, "ip": None, "resolves": None})

    return {"domain": domain, "total": len(results), "subdomains": resolved_list}


# ──────────────────────────────────────────────────────────────────────────────
# nmap fingerprinting
# ──────────────────────────────────────────────────────────────────────────────

NMAP_TIMEOUT_BASE     = 20      # seconds; also exposed to the UI via /api/config
NMAP_TIMEOUT_PER_PORT = 4


def find_nmap() -> Optional[str]:
    """Return the absolute path to the nmap binary, or None if not found."""
    path = shutil.which("nmap")
    if path:
        return path
    if sys.platform == "win32":
        for candidate in (
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\nmap\nmap.exe",
        ):
            if os.path.isfile(candidate):
                return candidate
    return None


async def run_nmap(ip: str, ports_str: str, timeout_seconds: int) -> dict:
    """
    Run ``nmap -sV`` against ``ip`` on ``ports_str``.

    Error handling
    ──────────────
    • asyncio.TimeoutError  → terminate → wait → kill → return ``{"_error": "nmap_timeout"}``
    • asyncio.CancelledError → terminate → wait → kill → **re-raise** (FastAPI handles it)
    • Other exceptions      → logged, returned as ``{"_error": "<msg>"}``
    """
    nmap_bin = find_nmap()
    if not nmap_bin:
        logger.warning("nmap_not_found")
        return {"_error": "nmap_not_installed"}

    args = [
        nmap_bin,
        "-sV", "--version-intensity", "7",
        "--script", "banner",
        "-Pn", "-T4",
        "--host-timeout", f"{timeout_seconds}s",
        "-p", ports_str,
        "-oX", "-",
        ip,
    ]

    logger.info("nmap_start", ip=ip, ports=ports_str, timeout=timeout_seconds)
    proc: Optional[asyncio.subprocess.Process] = None

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_seconds + 10
            )
        except TimeoutError:
            await _terminate(proc)
            logger.warning("nmap_timeout", ip=ip)
            return {"_error": "nmap_timeout"}
    except asyncio.CancelledError:
        # Reap nmap, then propagate so FastAPI can finish the cancellation.
        await _cleanup_after_cancel(proc)
        raise
    except Exception as exc:
        logger.error("nmap_unexpected", ip=ip, error=str(exc))
        if proc is not None:
            await _terminate(proc)
        return {"_error": str(exc)}

    if proc.returncode != 0 and not stdout:
        err = stderr.decode("utf-8", errors="replace")[:200]
        if "nmap" in err.lower() or "command not found" in err.lower():
            return {"_error": "nmap_not_installed"}
        return {"_error": err or "nmap error"}

    result = _parse_nmap_xml(stdout.decode("utf-8", errors="replace"))
    logger.info("nmap_done", ip=ip, ports_detected=len(result))
    return result


def _parse_nmap_xml(xml: str) -> dict:
    results: dict = {}
    try:
        # Output of our own nmap process (remote data inside it is escaped by
        # nmap); expat also refuses external entities and entity bombs.
        root = ET.fromstring(xml)  # noqa: S314
        for host in root.findall("host"):
            for ports_el in host.findall("ports"):
                for port_el in ports_el.findall("port"):
                    portid   = int(port_el.get("portid", 0))
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    # NB: an Element without children is falsy, so never use
                    # ``find(...) or default`` here — compare against None.
                    svc = port_el.find("service")
                    if svc is not None:
                        product   = svc.get("product", "")
                        version   = svc.get("version", "")
                        extrainfo = svc.get("extrainfo", "")
                        name      = svc.get("name", "")
                        cpe_el    = svc.find("cpe")
                        cpe       = (cpe_el.text or "") if cpe_el is not None else ""
                    else:
                        product = version = extrainfo = name = cpe = ""

                    banner = ""
                    if not product and not version:
                        for script_el in port_el.findall("script"):
                            if script_el.get("id") == "banner":
                                banner = script_el.get("output", "").strip()
                                break

                    results[portid] = {
                        "product":   product,
                        "version":   version,
                        "extrainfo": extrainfo,
                        "banner":    banner,
                        "cpe":       cpe,
                        "name":      name,
                    }
    except ET.ParseError as exc:
        results["_error"] = f"xml_parse_error: {exc}"
    return results


def nmap_timeout(port_count: int) -> int:
    """Return a sensible nmap wall-clock timeout in seconds for ``port_count`` ports."""
    return NMAP_TIMEOUT_BASE + NMAP_TIMEOUT_PER_PORT * port_count


# ──────────────────────────────────────────────────────────────────────────────
# Playwright screenshot — shared browser instance
# ──────────────────────────────────────────────────────────────────────────────

# Chromium never talks to the network by itself: every request is intercepted
# by ``_proxy_route`` and served through the SSRF-safe fetcher.  As a second
# line of defence anything that escapes interception (e.g. WebSockets) is
# sent to a dead proxy on 127.0.0.1:9 — ``<-loopback>`` removes Chromium's
# implicit proxy bypass for localhost — and hostname resolution is disabled.
BROWSER_ARGS: list[str] = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--proxy-server=http://127.0.0.1:9",
    "--proxy-bypass-list=<-loopback>",
    "--host-resolver-rules=MAP * ~NOTFOUND",
]

SCREENSHOT_MAX_REQUESTS      = 150              # per page
SCREENSHOT_MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # per sub-resource

# Hop-by-hop / encoding headers that must not be forwarded.
_DROP_REQUEST_HEADERS  = frozenset({
    "host", "connection", "content-length", "accept-encoding",
    "proxy-authorization", "proxy-connection", "keep-alive", "upgrade",
    "transfer-encoding", "te",
})
_DROP_RESPONSE_HEADERS = frozenset({
    "content-encoding", "content-length", "transfer-encoding", "connection",
    "keep-alive",
})


def screenshot_url(host: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    netloc = f"[{host}]" if ":" in host else host
    return (
        f"{scheme}://{netloc}"
        if (scheme, port) in (("http", 80), ("https", 443))
        else f"{scheme}://{netloc}:{port}"
    )


class _RouteProxy:
    """
    Playwright route handler that fetches every request with ``safe_http``.

    ``pins`` holds the SSRF-validated target (hostname → IP); other hosts a
    page references are resolved and validated on demand.  Blocked or failed
    requests are aborted, so Chromium can never reach an internal address.
    """

    def __init__(self, client, pins: dict[str, str]) -> None:
        self.client   = client
        self.pins     = pins
        self.requests = 0
        self.blocked  = 0

    async def __call__(self, route, request) -> None:
        self.requests += 1
        if self.requests > SCREENSHOT_MAX_REQUESTS:
            await route.abort("blockedbyclient")
            return
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _DROP_REQUEST_HEADERS
        }
        try:
            resp = await safe_http.fetch(
                self.client,
                request.url,
                method=request.method,
                headers=headers,
                content=request.post_data_buffer,
                pinned=self.pins,
                max_redirects=0,           # Chromium follows redirects via us
                max_bytes=SCREENSHOT_MAX_RESPONSE_SIZE,
                timeout=8.0,
            )
        except safe_http.BlockedDestination as exc:
            self.blocked += 1
            logger.warning("screenshot_request_blocked", url=request.url, reason=str(exc))
            await route.abort("blockedbyclient")
            return
        except Exception as exc:
            logger.debug("screenshot_request_failed", url=request.url, error=str(exc))
            await route.abort("failed")
            return
        await route.fulfill(
            status=resp.status,
            headers={
                k: v for k, v in resp.headers.items()
                if k.lower() not in _DROP_RESPONSE_HEADERS
            },
            body=resp.body,
        )


async def take_screenshot(hostname: str, ip: str, port: int) -> None:
    """
    Capture a screenshot of ``hostname:port`` and store it in the TTL-LRU
    ``screenshot_cache`` (keyed by ``hostname``).

    ``ip`` is the SSRF-validated address of ``hostname``; the page is loaded
    through ``_RouteProxy`` pinned to it.

    Browser reuse
    ─────────────
    When a shared ``Browser`` has been registered via ``set_browser`` (the
    lifespan does it at startup) a fresh ``BrowserContext`` is opened per
    screenshot; otherwise a short-lived browser is launched (fallback).
    """
    url = screenshot_url(hostname, port)
    logger.info("screenshot_start", target=hostname, port=port, url=url)

    try:
        if _browser is not None:
            await _capture(_browser, hostname, ip, url, mode="shared")
            return
        await _screenshot_launch_browser(hostname, ip, url)
    finally:
        limits.screenshots.release()


async def _capture(browser, hostname: str, ip: str, url: str, mode: str) -> None:
    context = None
    client  = safe_http.make_client(timeout=8.0)
    proxy   = _RouteProxy(client, {hostname: ip})
    try:
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
            service_workers="block",       # SW fetches would bypass routing
            accept_downloads=False,
        )
        await context.route("**/*", proxy)
        page = await context.new_page()
        try:
            await asyncio.wait_for(
                page.goto(url, wait_until="domcontentloaded"),
                timeout=10.0,
            )
            png = await page.screenshot(full_page=False)
            screenshot_cache.set(hostname, {"png": png, "url": url, "ts": time.time()})
            logger.info(
                "screenshot_done", target=hostname, bytes=len(png), mode=mode,
                requests=proxy.requests, blocked=proxy.blocked,
            )
        except Exception as exc:
            logger.warning("screenshot_page_error", target=hostname, url=url, error=str(exc))
    except Exception as exc:
        logger.error("screenshot_context_error", target=hostname, error=str(exc))
    finally:
        if context is not None:
            try:
                await context.close()
            except Exception as exc:
                logger.warning("screenshot_context_close_error", error=str(exc))
        await client.aclose()


async def _screenshot_launch_browser(hostname: str, ip: str, url: str) -> None:
    """
    Fallback: launch a fresh Chromium instance, capture one screenshot, close.

    Used when no shared browser is registered (Playwright missing at startup,
    or unit tests that skip the lifespan).
    """
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=BROWSER_ARGS)
            try:
                await _capture(browser, hostname, ip, url, mode="fallback")
            finally:
                await browser.close()
    except ImportError:
        logger.warning("playwright_not_installed")
    except Exception as exc:
        logger.error("screenshot_error", target=hostname, error=str(exc))


# ──────────────────────────────────────────────────────────────────────────────
# Markdown report generation
# ──────────────────────────────────────────────────────────────────────────────

_MD_ESCAPES = str.maketrans({
    "\\": "\\\\", "`": "\\`", "|": "\\|", "*": "\\*", "_": "\\_",
    "[": "\\[", "]": "\\]", "<": "&lt;", ">": "&gt;",
    "\r": " ", "\n": " ",
})


def _md(value) -> str:
    """
    Escape a value for inline Markdown / table cells.

    Banners and headers come from the scanned host and the payload from the
    client, so ``|`` would break tables, backticks/brackets would inject
    formatting or links, and raw HTML would render in many viewers.
    """
    return ("" if value is None else str(value)).translate(_MD_ESCAPES)


def build_markdown_report(
    meta:    dict,
    results: list[dict],
    summary: dict,
    audit:   Optional[dict] = None,
) -> str:
    """Render a complete Markdown security report from scan data."""
    ts          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_info = meta.get("target") or {}
    lines: list[str] = []

    lines += [
        "# LukitaPort — Port Scan Report",
        "",
        f"> Generated: {ts}  ",
        f"> **Target:** {_md(target_info.get('input', '—'))}  ",
        f"> **IP:** {_md(target_info.get('ip', '—'))}  ",
    ]
    if target_info.get("hostname"):
        lines.append(f"> **Hostname:** {_md(target_info['hostname'])}  ")
    lines += [
        f"> **Mode:** {_md(target_info.get('mode', '—'))}  ",
        f"> **Profile:** {_md(target_info.get('profile', 'normal'))}  ",
    ]

    geo = target_info.get("geo") or {}
    if geo:
        lines.append(
            f"> **Location:** {_md(geo.get('city', ''))} {_md(geo.get('country', ''))} · "
            f"{_md(geo.get('isp', ''))} · {_md(geo.get('asn', ''))}  "
        )
    lines += [
        "> **For educational use only.**",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Open | Closed | Filtered | Total Scanned |",
        "|------|--------|----------|---------------|",
        f"| {_md(summary.get('open', 0))} | {_md(summary.get('closed', 0))} | "
        f"{_md(summary.get('filtered', 0))} | {_md(summary.get('total', 0))} |",
        "",
    ]

    open_ports = [r for r in results if r.get("state") == "open"]
    if open_ports:
        lines += [
            "## Open Ports",
            "",
            "| Port | Service | Risk | Response (ms) | Version / Banner |",
            "|------|---------|------|---------------|------------------|",
        ]
        for r in open_ports:
            port    = r.get("port", "")
            service = r.get("service", "")
            risk    = port_risk(port).upper()
            resp    = r.get("response_time_ms", "—")
            version = r.get("version") or r.get("banner") or ""
            lines.append(
                f"| {_md(port)} | {_md(service)} | {risk} | {_md(resp)} | {_md(str(version)[:60])} |"
            )
        lines.append("")

    risks  = [port_risk(r.get("port")) for r in open_ports]
    high_n = risks.count("high")
    med_n  = risks.count("medium")
    if high_n or med_n:
        lines += ["## Risk Assessment", ""]
        if high_n:
            lines.append(f"- 🔴 **{high_n} high-risk port(s)** — FTP, Telnet, RDP, exposed databases…")
        if med_n:
            lines.append(f"- 🟡 **{med_n} medium-risk port(s)** — SSH, DNS, IMAP, alternative proxies")
        lines.append("")

    lines += [
        "## All Results",
        "",
        "| Port | State | Service | Risk | Response (ms) |",
        "|------|-------|---------|------|---------------|",
    ]
    for r in results:
        port  = r.get("port", "")
        state = r.get("state", "")
        svc   = r.get("service", "")
        risk  = port_risk(port).upper() if state == "open" else "—"
        resp  = r.get("response_time_ms", "—")
        icon  = "🟢" if state == "open" else "🟡" if state == "filtered" else "🔴"
        lines.append(
            f"| {_md(port)} | {icon} {_md(str(state).capitalize())} | {_md(svc)} | {risk} | {_md(resp)} |"
        )
    lines.append("")

    if audit:
        lines += ["---", "", "## Advanced Audit", ""]
        hd = audit.get("headers")
        if hd and not hd.get("error"):
            lines.append(
                f"### HTTP Security Headers — Grade: {_md(hd.get('grade', '?'))} "
                f"({_md(hd.get('score', 0))}/100)"
            )
            lines.append("")
            for h in hd.get("missing", []):
                lines.append(
                    f"- {_md(h['header'])} (**{_md(str(h['severity']).upper())}**) "
                    f"— {_md(h.get('description_en', ''))}"
                )
            lines.append("")

        td = audit.get("technologies")
        if td and not td.get("error") and td.get("technologies"):
            lines.append(f"### Detected Technologies ({_md(td.get('count', 0))})")
            lines.append("")
            for tech in td["technologies"]:
                lines.append(
                    f"- {_md(tech['icon'])} **{_md(tech['name'])}** ({_md(tech['category'])})"
                )
            lines.append("")

        pd = audit.get("paths")
        if pd and pd.get("found"):
            lines.append(f"### Sensitive Paths ({_md(pd.get('total_found', 0))} found)")
            lines += [
                "",
                "| Path | Label | Severity | Status |",
                "|------|-------|----------|--------|",
            ]
            for f in pd["found"]:
                accessible = "✅ Accessible" if f["accessible"] else f"⚠️ {_md(f['status_code'])}"
                lines.append(
                    f"| {_md(f['path'])} | {_md(f['label'])} | "
                    f"**{_md(str(f['severity']).upper())}** | {accessible} |"
                )
            lines.append("")

    lines += ["---", "", "*LukitaPort · jaimefg1888 · For educational use only*"]
    return "\n".join(lines)
