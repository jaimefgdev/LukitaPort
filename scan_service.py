"""
scan_service.py
───────────────
Service layer for LukitaPort.

All heavy business logic previously scattered through ``main.py`` lives here.
FastAPI route handlers are thin wrappers that call these functions and return
typed responses.

Responsibilities
────────────────
• GeoIP enrichment
• Network discovery (ping sweep) with proper subprocess lifecycle
• Subdomain enumeration via crt.sh
• nmap fingerprinting with graceful CancelledError propagation
• Playwright screenshots — reuses a shared global browser instance
  (set by main.py lifespan via ``set_browser`` / ``clear_browser``)
• Markdown report building
"""

from __future__ import annotations

import asyncio
import re
import shutil
import socket
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import TYPE_CHECKING, Optional

import httpx

from cache import screenshot_cache
from config import PORT_RISK
from logging_config import get_logger

if TYPE_CHECKING:
    # Avoid a hard import of playwright at module level; it may not be installed.
    from playwright.async_api import Browser  # type: ignore[import]

logger = get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Global Playwright browser handle
# ──────────────────────────────────────────────────────────────────────────────
# The lifespan in main.py calls set_browser() / clear_browser().
# take_screenshot() uses the shared instance so that Chromium only starts once
# per server process instead of once per screenshot request.
# ──────────────────────────────────────────────────────────────────────────────

_browser: Optional["Browser"] = None


def set_browser(browser: "Browser") -> None:
    """
    Register a live Playwright ``Browser`` instance.

    Called by the FastAPI lifespan handler immediately after launching
    Chromium.  Must be called before any ``take_screenshot`` invocations.
    """
    global _browser
    _browser = browser
    logger.info("playwright_browser_registered")


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
    """Return GeoIP enrichment data for ``ip``.  Never raises."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={
                    "fields": "status,country,countryCode,regionName,city,isp,as,org,query"
                },
            )
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country":      data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "region":       data.get("regionName", ""),
                    "city":         data.get("city", ""),
                    "isp":          data.get("isp", ""),
                    "asn":          data.get("as", ""),
                    "org":          data.get("org", ""),
                }
    except Exception as exc:  # noqa: BLE001
        logger.warning("geoip_failed", ip=ip, error=str(exc))
    return {}


# ──────────────────────────────────────────────────────────────────────────────
# Ping sweep / network discovery
# ──────────────────────────────────────────────────────────────────────────────

_IS_WINDOWS = sys.platform == "win32"


def _kill_proc(proc: asyncio.subprocess.Process) -> None:
    """Terminate → kill, silently ignoring ProcessLookupError."""
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    except Exception:  # noqa: BLE001
        pass


async def _ping_one(ip_str: str) -> Optional[dict]:
    """
    Ping a single IP address.

    Guarantees subprocess cleanup on timeout, CancelledError, and any
    unexpected exception.  Returns None when the host is unreachable.
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
        except (asyncio.TimeoutError, asyncio.CancelledError):
            _kill_proc(proc)
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

    except (OSError, Exception) as exc:  # noqa: BLE001
        logger.debug("ping_error", ip=ip_str, error=str(exc))
        if proc:
            _kill_proc(proc)
    return None


async def ping_sweep(hosts: list, concurrency: int = 64) -> list[dict]:
    """
    Ping all hosts concurrently (max ``concurrency`` at once).

    Returns a list of alive-host dicts sorted ascending by IP octet.
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
    alive.sort(key=lambda x: list(map(int, x["ip"].split("."))))
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
    except Exception as exc:  # noqa: BLE001
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
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, item["subdomain"])
            return {**item, "ip": ip, "resolves": True}
        except Exception:  # noqa: BLE001
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

_NMAP_TIMEOUT_BASE     = 20
_NMAP_TIMEOUT_PER_PORT = 4


def find_nmap() -> Optional[str]:
    """Return the absolute path to the nmap binary, or None if not found."""
    path = shutil.which("nmap")
    if path:
        return path
    if sys.platform == "win32":
        import os
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
    • asyncio.TimeoutError  → terminate → kill → return ``{"_error": "nmap_timeout"}``
    • asyncio.CancelledError → terminate → kill → **re-raise** (FastAPI handles it)
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
        except asyncio.TimeoutError:
            _kill_proc(proc)
            logger.warning("nmap_timeout", ip=ip)
            return {"_error": "nmap_timeout"}
        except asyncio.CancelledError:
            _kill_proc(proc)
            raise  # propagate so FastAPI can send a proper cancellation response

        if proc.returncode != 0 and not stdout:
            err = stderr.decode("utf-8", errors="replace")[:200]
            if "nmap" in err.lower() or "command not found" in err.lower():
                return {"_error": "nmap_not_installed"}
            return {"_error": err or "nmap error"}

        result = _parse_nmap_xml(stdout.decode("utf-8", errors="replace"))
        logger.info("nmap_done", ip=ip, ports_detected=len(result))
        return result

    except asyncio.CancelledError:
        if proc:
            _kill_proc(proc)
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("nmap_unexpected", ip=ip, error=str(exc))
        return {"_error": str(exc)}


def _parse_nmap_xml(xml: str) -> dict:
    results: dict = {}
    try:
        root = ET.fromstring(xml)
        for host in root.findall("host"):
            for ports_el in host.findall("ports"):
                for port_el in ports_el.findall("port"):
                    portid   = int(port_el.get("portid", 0))
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    svc = port_el.find("service") or {}

                    def _sget(el, attr: str) -> str:  # noqa: ANN001
                        return el.get(attr, "") if hasattr(el, "get") else ""

                    product   = _sget(svc, "product")
                    version   = _sget(svc, "version")
                    extrainfo = _sget(svc, "extrainfo")
                    name      = _sget(svc, "name")
                    cpe_el    = svc.find("cpe") if hasattr(svc, "find") else None  # type: ignore[union-attr]
                    cpe       = cpe_el.text if cpe_el is not None else ""

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
    return _NMAP_TIMEOUT_BASE + _NMAP_TIMEOUT_PER_PORT * port_count


# ──────────────────────────────────────────────────────────────────────────────
# Playwright screenshot — shared browser instance
# ──────────────────────────────────────────────────────────────────────────────

async def take_screenshot(target: str, port: int) -> None:
    """
    Capture a full-browser screenshot of ``target:port`` and store it in the
    TTL-LRU ``screenshot_cache``.

    Browser reuse
    ─────────────
    When a shared ``Browser`` instance has been registered via ``set_browser``
    (which main.py's lifespan does at startup), this function opens a fresh
    ``BrowserContext`` per screenshot request instead of launching a new
    Chromium process.  A context is lighter than a browser: it has its own
    cookies/localStorage/network but shares the underlying Chromium renderer.
    The context is always closed in the ``finally`` block to prevent leaks.

    Fallback
    ────────
    If ``_browser`` is None (e.g. Playwright not installed, or called from
    a test without a lifespan), the function falls back to launching a
    short-lived browser instance — the old behaviour — so nothing breaks.
    """
    scheme = "https" if port in (443, 8443) else "http"
    url    = (
        f"{scheme}://{target}:{port}"
        if port not in (80, 443)
        else f"{scheme}://{target}"
    )

    logger.info("screenshot_start", target=target, port=port, url=url)

    # ── Path A: reuse shared browser (production path) ────────────────────────
    if _browser is not None:
        await _screenshot_with_shared_browser(target, url)
        return

    # ── Path B: launch a dedicated browser (fallback / test path) ────────────
    await _screenshot_launch_browser(target, url)


async def _screenshot_with_shared_browser(target: str, url: str) -> None:
    """
    Capture a screenshot using the pre-launched global ``_browser``.

    Each call opens an isolated ``BrowserContext`` (separate cookies, cache,
    TLS session) and closes it unconditionally in ``finally``.  This means
    concurrent requests never interfere and the context is always freed.
    """
    context = None
    try:
        context = await _browser.new_context(  # type: ignore[union-attr]
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
        )
        page = await context.new_page()
        try:
            await asyncio.wait_for(
                page.goto(url, wait_until="domcontentloaded"),
                timeout=8.0,
            )
            png = await page.screenshot(full_page=False)
            screenshot_cache.set(target, {"png": png, "url": url, "ts": time.time()})
            logger.info("screenshot_done", target=target, bytes=len(png), mode="shared")
        except Exception as exc:  # noqa: BLE001
            logger.warning("screenshot_page_error", target=target, url=url, error=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.error("screenshot_context_error", target=target, error=str(exc))
    finally:
        if context is not None:
            try:
                await context.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("screenshot_context_close_error", error=str(exc))


async def _screenshot_launch_browser(target: str, url: str) -> None:
    """
    Fallback: launch a fresh Chromium instance, capture one screenshot, close.

    Used when ``_browser`` is None (Playwright not installed, or unit tests
    that skip the lifespan).
    """
    try:
        from playwright.async_api import async_playwright  # type: ignore[import]
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    ignore_https_errors=True,
                )
                page = await context.new_page()
                try:
                    await asyncio.wait_for(
                        page.goto(url, wait_until="domcontentloaded"),
                        timeout=8.0,
                    )
                    png = await page.screenshot(full_page=False)
                    screenshot_cache.set(target, {"png": png, "url": url, "ts": time.time()})
                    logger.info("screenshot_done", target=target, bytes=len(png), mode="fallback")
                except Exception as exc:  # noqa: BLE001
                    logger.warning("screenshot_page_error", target=target, error=str(exc))
                finally:
                    await context.close()
            finally:
                await browser.close()
    except ImportError:
        logger.warning("playwright_not_installed")
    except Exception as exc:  # noqa: BLE001
        logger.error("screenshot_error", target=target, error=str(exc))


# ──────────────────────────────────────────────────────────────────────────────
# Markdown report generation
# ──────────────────────────────────────────────────────────────────────────────

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
        f"> **Target:** `{target_info.get('input', '—')}`  ",
        f"> **IP:** `{target_info.get('ip', '—')}`  ",
    ]
    if target_info.get("hostname"):
        lines.append(f"> **Hostname:** `{target_info['hostname']}`  ")
    lines += [
        f"> **Mode:** {target_info.get('mode', '—')}  ",
        f"> **Profile:** {target_info.get('profile', 'normal')}  ",
    ]

    geo = target_info.get("geo") or {}
    if geo:
        lines.append(
            f"> **Location:** {geo.get('city', '')} {geo.get('country', '')} · "
            f"{geo.get('isp', '')} · {geo.get('asn', '')}  "
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
        f"| {summary.get('open', 0)} | {summary.get('closed', 0)} | "
        f"{summary.get('filtered', 0)} | {summary.get('total', 0)} |",
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
            risk    = PORT_RISK.get(port, "info").upper()
            resp    = r.get("response_time_ms", "—")
            version = r.get("version") or r.get("banner") or ""
            lines.append(f"| {port} | {service} | {risk} | {resp} | {str(version)[:60]} |")
        lines.append("")

    high_n = sum(1 for r in open_ports if PORT_RISK.get(r.get("port"), "info") == "high")
    med_n  = sum(1 for r in open_ports if PORT_RISK.get(r.get("port"), "info") == "medium")
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
        risk  = PORT_RISK.get(port, "info").upper() if state == "open" else "—"
        resp  = r.get("response_time_ms", "—")
        icon  = "🟢" if state == "open" else "🟡" if state == "filtered" else "🔴"
        lines.append(f"| {port} | {icon} {state.capitalize()} | {svc} | {risk} | {resp} |")
    lines.append("")

    if audit:
        lines += ["---", "", "## Advanced Audit", ""]
        hd = audit.get("headers")
        if hd and not hd.get("error"):
            lines.append(
                f"### HTTP Security Headers — Grade: {hd.get('grade', '?')} "
                f"({hd.get('score', 0)}/100)"
            )
            lines.append("")
            for h in hd.get("missing", []):
                lines.append(
                    f"- `{h['header']}` (**{h['severity'].upper()}**) "
                    f"— {h.get('description_en', '')}"
                )
            lines.append("")

        td = audit.get("technologies")
        if td and not td.get("error") and td.get("technologies"):
            lines.append(f"### Detected Technologies ({td['count']})")
            lines.append("")
            for tech in td["technologies"]:
                lines.append(f"- {tech['icon']} **{tech['name']}** ({tech['category']})")
            lines.append("")

        pd = audit.get("paths")
        if pd and pd.get("found"):
            lines.append(f"### Sensitive Paths ({pd['total_found']} found)")
            lines += [
                "",
                "| Path | Label | Severity | Status |",
                "|------|-------|----------|--------|",
            ]
            for f in pd["found"]:
                accessible = "✅ Accessible" if f["accessible"] else f"⚠️ {f['status_code']}"
                lines.append(
                    f"| `{f['path']}` | {f['label']} | "
                    f"**{f['severity'].upper()}** | {accessible} |"
                )
            lines.append("")

    lines += ["---", "", "*LukitaPort · jaimefg1888 · For educational use only*"]
    return "\n".join(lines)
