"""
auditor.py
──────────
HTTP header auditing, technology detection, and sensitive-path scanning.

Key improvements over v1
────────────────────────
• Technology signatures loaded from ``tech_signatures.json`` at import time.
  Drop-in extensibility: add new entries to the JSON with no Python changes.
  Falls back to an empty list if the file is missing (non-fatal).
• Each sub-audit is fully type-annotated and returns dicts compatible with
  the Pydantic models in ``models.py``.
• Structured logging replaces all print() calls.
• One HTTP session is created per ``run_full_audit`` call and shared across
  all concurrent sub-tasks.  All requests go through ``safe_http`` (pinned
  target IP, SSRF-checked redirects, bounded response size).
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Optional

import safe_http
from logging_config import get_logger

logger = get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Tech signatures — loaded from JSON for extensibility
# ──────────────────────────────────────────────────────────────────────────────

_SIG_FILE = Path(__file__).parent / "tech_signatures.json"

def _compile(pattern: str, where: str) -> Optional[re.Pattern]:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except (re.error, TypeError) as exc:
        logger.warning("tech_signature_invalid_regex", where=where, pattern=pattern, error=str(exc))
        return None


def _load_signatures() -> list[dict]:
    """
    Load and pre-compile signatures.  Each entry gets ``_body`` (compiled
    body regexes) and ``_headers`` (lower-cased header → compiled regex);
    invalid patterns are logged and skipped instead of failing every audit.
    """
    try:
        with _SIG_FILE.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.warning("tech_signatures_missing", path=str(_SIG_FILE))
        return []
    except json.JSONDecodeError as exc:
        logger.error("tech_signatures_invalid_json", error=str(exc))
        return []

    compiled: list[dict] = []
    for sig in data:
        name = sig.get("name", "")
        body = [c for c in (_compile(p, name) for p in sig.get("body", [])) if c]
        headers = {
            hk.lower(): c
            for hk, hp in sig.get("headers", {}).items()
            if (c := _compile(hp, f"{name}:{hk}"))
        }
        compiled.append({**sig, "_body": body, "_headers": headers})
    logger.info("tech_signatures_loaded", count=len(compiled), path=str(_SIG_FILE))
    return compiled


TECH_SIGNATURES: list[dict] = _load_signatures()


def reload_signatures() -> int:
    """Hot-reload signatures from disk.  Returns new count."""
    global TECH_SIGNATURES
    TECH_SIGNATURES = _load_signatures()
    return len(TECH_SIGNATURES)


# ──────────────────────────────────────────────────────────────────────────────
# HTTP session — SSRF-safe (see safe_http.py)
# ──────────────────────────────────────────────────────────────────────────────

class _AuditSession:
    """
    Wraps an httpx client plus the host→IP pins for one audit.

    The audit target is pinned to the IP validated by the API layer, so no
    request of this audit re-resolves it; redirects to other hosts are
    resolved and SSRF-checked hop by hop by ``safe_http.fetch``.
    """

    def __init__(self, pins: dict[str, str], timeout: float = 6.0) -> None:
        self.pins   = pins
        self.client = safe_http.make_client(timeout)

    async def __aenter__(self) -> "_AuditSession":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.client.aclose()

    async def get(
        self, url: str, timeout: float = 6.0, max_redirects: int = 5,
    ) -> safe_http.SafeResponse:
        return await safe_http.fetch(
            self.client, url, pinned=self.pins,
            timeout=timeout, max_redirects=max_redirects,
        )


async def _fetch(
    client:  _AuditSession,
    url:     str,
    timeout: float = 6.0,
) -> Optional[tuple[int, dict[str, str], str]]:
    try:
        resp = await client.get(url, timeout=timeout)
        return resp.status, dict(resp.headers), resp.text
    except safe_http.BlockedDestination as exc:
        logger.warning("fetch_blocked", url=url, reason=str(exc))
        return None
    except Exception as exc:  # noqa: BLE001
        logger.debug("fetch_failed", url=url, error=str(exc))
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Pre-fetch (single canonical request shared by all sub-audits)
# ──────────────────────────────────────────────────────────────────────────────

# (scheme, port) candidates in order of preference.
_WEB_PORTS: tuple[tuple[str, int], ...] = (
    ("https", 443), ("https", 8443), ("http", 80), ("http", 8080), ("http", 8888),
)


def _base_url(scheme: str, target: str, port: int) -> str:
    host = f"[{target}]" if ":" in target else target
    default = (scheme, port) in (("https", 443), ("http", 80))
    return f"{scheme}://{host}" if default else f"{scheme}://{host}:{port}"


def _candidate_base_urls(target: str, open_ports: list[int]) -> list[str]:
    """
    Base URLs to try, including the port when it is not the scheme default
    (auditing ``http://target`` when only 8080 is open would hit port 80).
    """
    urls = [_base_url(scheme, target, port) for scheme, port in _WEB_PORTS if port in open_ports]
    return urls or [_base_url("https", target, 443), _base_url("http", target, 80)]


def _choose_base_url(target: str, open_ports: list[int]) -> str:
    return _candidate_base_urls(target, open_ports)[0]


async def _prefetch(
    target: str,
    open_ports: list[int],
    client: _AuditSession,
) -> tuple[str, Optional[tuple[int, dict[str, str], str]]]:
    candidates = _candidate_base_urls(target, open_ports)
    for base_url in candidates:
        result = await _fetch(client, base_url)
        if result is not None:
            return base_url, result
    return candidates[0], None


# ──────────────────────────────────────────────────────────────────────────────
# HTTP Security Headers audit
# ──────────────────────────────────────────────────────────────────────────────

SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "label":          "HSTS",
        "description_es": "Obliga a usar HTTPS. Previene ataques de downgrade y cookies robadas.",
        "description_en": "Forces HTTPS. Prevents downgrade attacks and cookie theft.",
        "severity":       "high",
        "example":        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "label":          "CSP",
        "description_es": "Limita las fuentes de scripts y recursos. Mitiga XSS.",
        "description_en": "Restricts script/resource sources. Mitigates XSS.",
        "severity":       "high",
        "example":        "Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Frame-Options": {
        "label":          "X-Frame-Options",
        "description_es": "Previene que la página sea cargada en un iframe (clickjacking).",
        "description_en": "Prevents the page from being loaded in an iframe (clickjacking).",
        "severity":       "medium",
        "example":        "X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "label":          "X-Content-Type-Options",
        "description_es": "Evita que el navegador interprete el contenido con un MIME diferente.",
        "description_en": "Prevents MIME type sniffing.",
        "severity":       "medium",
        "example":        "X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "label":          "Referrer-Policy",
        "description_es": "Controla qué información del referer se envía en las peticiones.",
        "description_en": "Controls how much referrer info is sent with requests.",
        "severity":       "low",
        "example":        "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "label":          "Permissions-Policy",
        "description_es": "Controla el acceso a APIs del navegador (cámara, micrófono, geolocalización).",
        "description_en": "Controls access to browser APIs (camera, mic, geolocation).",
        "severity":       "low",
        "example":        "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "label":          "X-XSS-Protection",
        "description_es": "Filtro XSS del navegador (legacy, pero sigue siendo buena práctica).",
        "description_en": "Browser XSS filter (legacy, but still good practice).",
        "severity":       "low",
        "example":        "X-XSS-Protection: 1; mode=block",
    },
}

DANGEROUS_HEADERS: dict[str, str] = {
    "Server":              "Reveals server software and version.",
    "X-Powered-By":        "Reveals backend language/framework.",
    "X-AspNet-Version":    "Reveals ASP.NET version.",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version.",
}


def _audit_headers_from_prefetch(
    base_url: str,
    prefetch: Optional[tuple[int, dict[str, str], str]],
) -> dict:
    if prefetch is None:
        return {
            "error": "Could not connect", "url": base_url,
            "present": [], "missing": [], "dangerous": [], "score": 0, "grade": "F",
        }

    status, headers, _ = prefetch
    headers_norm       = {k.title(): v for k, v in headers.items()}

    present: list[dict] = []
    missing: list[dict] = []

    for header, info in SECURITY_HEADERS.items():
        entry = {
            "header":         header,
            "label":          info["label"],
            "description_es": info["description_es"],
            "description_en": info["description_en"],
            "severity":       info["severity"],
            "example":        info.get("example", ""),
        }
        if header.title() in headers_norm:
            entry["value"]  = headers_norm[header.title()]
            entry["status"] = "present"
            present.append(entry)
        else:
            entry["status"] = "missing"
            missing.append(entry)

    dangerous = [
        {
            "header":      h,
            "value":       headers_norm[h.title()],
            "description": desc,
        }
        for h, desc in DANGEROUS_HEADERS.items()
        if h.title() in headers_norm
    ]

    high_p = sum(1 for h in present if h["severity"] == "high")
    med_p  = sum(1 for h in present if h["severity"] == "medium")
    low_p  = sum(1 for h in present if h["severity"] == "low")
    score  = max(0, min(100, high_p * 30 + med_p * 20 + low_p * 10 - len(dangerous) * 5))
    grade  = (
        "A" if score >= 90 else
        "B" if score >= 75 else
        "C" if score >= 55 else
        "D" if score >= 35 else
        "F"
    )

    logger.debug(
        "headers_audited",
        url=base_url,
        score=score,
        grade=grade,
        missing_count=len(missing),
    )
    return {
        "url":         base_url,
        "status_code": status,
        "present":     present,
        "missing":     missing,
        "dangerous":   dangerous,
        "score":       score,
        "grade":       grade,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Technology detection — reads from TECH_SIGNATURES (loaded from JSON)
# ──────────────────────────────────────────────────────────────────────────────

async def _detect_technologies_from_prefetch(
    base_url: str,
    prefetch: Optional[tuple[int, dict[str, str], str]],
    client:   _AuditSession,
) -> dict:
    if prefetch is None:
        return {"error": "Could not connect", "url": base_url, "technologies": []}

    status, headers, body = prefetch

    # Fetch a few extra pages to improve detection accuracy
    extra_body = ""
    for extra in ("/wp-json/wp/v2/", "/feed/", "/wp-login.php"):
        r = await _fetch(client, base_url.rstrip("/") + extra, timeout=3.0)
        if r and r[0] in (200, 301, 302):
            extra_body += r[2]
            break

    full_body    = body + extra_body
    headers_norm = {k.lower(): v for k, v in headers.items()}

    # Generator meta tag
    gen_match = (
        re.search(
            r'<meta[^>]+name=[\"\'\`]generator[\"\'\`][^>]+content=[\"\'\`]([^\"\'\`]+)[\"\'\`]',
            full_body, re.IGNORECASE,
        )
        or re.search(
            r'<meta[^>]+content=[\"\'\`]([^\"\'\`]+)[\"\'\`][^>]+name=[\"\'\`]generator[\"\'\`]',
            full_body, re.IGNORECASE,
        )
    )
    generator = gen_match.group(1) if gen_match else ""

    detected:       list[dict] = []
    detected_names: set[str]   = set()

    # Prioritise generator meta over pattern matching for CMS
    if generator:
        gen_lower = generator.lower()
        ver_m     = re.search(r"\d[\d.]*", generator)
        ver       = ver_m.group() if ver_m else ""
        for cms in ("wordpress", "joomla", "drupal"):
            if cms in gen_lower:
                detected.append({
                    "name": cms.capitalize(), "icon": "📝",
                    "category": "CMS", "version": ver,
                })
                detected_names.add(cms.capitalize())
                break

    # Pattern matching from JSON signatures
    for sig in TECH_SIGNATURES:
        name = sig.get("name", "")
        if name in detected_names:
            continue

        # Body patterns (pre-compiled at load time)
        found = any(rx.search(full_body) for rx in sig.get("_body", []))

        # Header patterns
        if not found:
            for hk, rx in sig.get("_headers", {}).items():
                hv = headers_norm.get(hk, "")
                if hv and rx.search(hv):
                    found = True
                    break

        if found:
            detected.append({
                "name":     name,
                "icon":     sig.get("icon", "⚙️"),
                "category": sig.get("category", "Other"),
            })
            detected_names.add(name)

    # Group by category
    by_category: dict[str, list[dict]] = {}
    for tech in detected:
        by_category.setdefault(tech["category"], []).append(tech)

    logger.debug(
        "tech_detected",
        url=base_url,
        count=len(detected),
        technologies=[t["name"] for t in detected],
    )
    return {
        "url":          base_url,
        "status_code":  status,
        "technologies": detected,
        "by_category":  by_category,
        "count":        len(detected),
        "generator":    generator,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Sensitive path scanner
# ──────────────────────────────────────────────────────────────────────────────

SENSITIVE_PATHS: list[tuple[str, str, str, str]] = [
    ("/robots.txt",        "Robots.txt",         "info",   "May reveal hidden paths"),
    ("/sitemap.xml",       "Sitemap",             "info",   "Site structure map"),
    ("/.git/HEAD",         ".git exposed",        "high",   "Git repo accessible publicly"),
    ("/.env",              ".env exposed",        "high",   "Env vars exposed"),
    ("/config.php",        "config.php",          "high",   "Config file exposed"),
    ("/configuration.php", "configuration.php",   "high",   "Joomla config exposed"),
    ("/wp-config.php",     "wp-config.php",       "high",   "WordPress config exposed"),
    ("/phpinfo.php",       "phpinfo()",           "high",   "PHP server info exposed"),
    ("/info.php",          "info.php",            "high",   "Server info exposed"),
    ("/wp-admin/",         "WordPress Admin",     "medium", "WordPress admin panel"),
    ("/admin/",            "Admin Panel",         "medium", "Generic admin panel"),
    ("/administrator/",    "Joomla Admin",        "medium", "Joomla admin panel"),
    ("/login",             "Login",               "info",   "Login page"),
    ("/dashboard",         "Dashboard",           "info",   "Dashboard"),
    ("/phpmyadmin/",       "phpMyAdmin",          "high",   "DB interface exposed"),
    ("/pma/",              "phpMyAdmin (pma)",    "high",   "Alt phpMyAdmin"),
    ("/api/",              "API Root",            "info",   "API root endpoint"),
    ("/swagger-ui.html",   "Swagger UI",          "medium", "API docs exposed"),
    ("/swagger/",          "Swagger",             "medium", "API documentation"),
    ("/api/docs",          "API Docs",            "medium", "API documentation"),
    ("/graphql",           "GraphQL",             "medium", "GraphQL endpoint exposed"),
    ("/debug",             "Debug endpoint",      "high",   "Debug endpoint exposed"),
    ("/console",           "Console",             "high",   "Admin console exposed"),
    ("/backup/",           "Backup dir",          "high",   "Backup directory exposed"),
    ("/logs/",             "Logs dir",            "high",   "Logs directory exposed"),
    ("/error_log",         "Error log",           "medium", "Error log exposed"),
    ("/.htaccess",         ".htaccess",           "medium", "Apache config exposed"),
    ("/web.config",        "web.config",          "high",   "IIS config exposed"),
    ("/server-status",     "Apache Status",       "medium", "Apache server status"),
    ("/server-info",       "Apache Info",         "medium", "Server info page"),
]


async def _scan_sensitive_paths(
    base_url: str,
    client:   _AuditSession,
    timeout:  float = 4.0,
) -> dict:
    async def check_one(path_tuple: tuple[str, str, str, str]) -> Optional[dict]:
        path, label, severity, description = path_tuple
        url = base_url.rstrip("/") + path
        try:
            # Redirects are reported as-is (not followed) for path probes.
            resp = await client.get(url, timeout=timeout, max_redirects=0)
            code = resp.status
            if code in (200, 301, 302, 403):
                return {
                    "path":         path,
                    "label":        label,
                    "severity":     severity,
                    "description":  description,
                    "status_code":  code,
                    "content_type": resp.headers.get("content-type", ""),
                    "size_bytes":   len(resp.body),
                    "url":          resp.url,
                    "accessible":   code == 200,
                }
        except safe_http.BlockedDestination as exc:
            logger.warning("path_check_blocked", url=url, reason=str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.debug("path_check_failed", url=url, error=str(exc))
        return None

    tasks = [asyncio.create_task(check_one(pt)) for pt in SENSITIVE_PATHS]
    raw   = await asyncio.gather(*tasks, return_exceptions=True)

    found:     list[dict] = []
    not_found: int        = 0
    errors:    int        = 0

    for r in raw:
        if isinstance(r, Exception):
            errors += 1
        elif r is None:
            not_found += 1
        else:
            found.append(r)

    found.sort(key=lambda x: {"high": 0, "medium": 1, "info": 2}.get(x["severity"], 9))

    high_count   = sum(1 for f in found if f["severity"] == "high"   and f["accessible"])
    medium_count = sum(1 for f in found if f["severity"] == "medium" and f["accessible"])

    logger.info(
        "paths_scanned",
        base_url=base_url,
        total_found=len(found),
        high=high_count,
        medium=medium_count,
    )
    return {
        "base_url":    base_url,
        "found":       found,
        "not_found":   not_found,
        "errors":      errors,
        "high_count":  high_count,
        "medium_count": medium_count,
        "total_found": len(found),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

async def run_full_audit(
    target:     str,
    open_ports: list[int],
    pinned_ip:  Optional[str] = None,
) -> dict:
    """
    Run all three audit modules concurrently against ``target``.

    ``pinned_ip`` is the SSRF-validated address of ``target``; every request
    to ``target`` connects there (``target`` is only sent as Host/SNI).

    Returns a dict with keys: ``headers``, ``technologies``, ``paths``.
    """
    logger.info("audit_start", target=target, open_ports=open_ports)
    pins = {target: pinned_ip} if pinned_ip else {}
    async with _AuditSession(pins) as client:
        base_url, prefetch = await _prefetch(target, open_ports, client)
        headers_result = _audit_headers_from_prefetch(base_url, prefetch)
        tech_result, paths_result = await asyncio.gather(
            _detect_technologies_from_prefetch(base_url, prefetch, client),
            _scan_sensitive_paths(base_url, client),
        )

    logger.info("audit_done", target=target, grade=headers_result.get("grade"))
    return {
        "headers":      headers_result,
        "technologies": tech_result,
        "paths":        paths_result,
    }
