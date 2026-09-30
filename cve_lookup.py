"""
cve_lookup.py
─────────────
Async NVD CVE lookup with:
  • Rate limiting: requests are spaced 6.2 s apart (NVD public limit), or
    0.6 s with an API key (``NVD_API_KEY``).  The spacing lock is held only
    around the request itself — never while backing off — so one throttled
    lookup does not stall every other caller.
  • Exponential back-off (jittered) on 429 / 5xx / transport errors,
    honouring ``Retry-After`` in both delta-seconds and HTTP-date forms.
  • Bounded TTL-LRU cache (10 min, 500 entries).
  • Precise queries: by CPE (``virtualMatchString``) when nmap provided one
    with a version, else by ``"<product> <version>"``.  Ports without a
    known product *and* version are skipped rather than searched by bare
    service name, which only returned noise.
"""

from __future__ import annotations

import asyncio
import os
import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

import httpx

from cache import TTLLRUCache
from logging_config import get_logger

logger = get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

NVD_API_BASE           = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT        = 12.0
RESULTS_PER_PAGE       = 5
NVD_REQUEST_DELAY      = 6.2   # 5 requests / 30 s without an API key
NVD_REQUEST_DELAY_KEY  = 0.6   # 50 requests / 30 s with an API key

# Back-off settings
_BACKOFF_BASE     = 2.0   # seconds
_BACKOFF_MAX      = 60.0  # cap
_BACKOFF_JITTER   = 0.5   # ± fraction of computed wait
_MAX_RETRIES      = 4

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#ff0033",
    "HIGH":     "#ff4444",
    "MEDIUM":   "#ffaa00",
    "LOW":      "#00cc66",
    "NONE":     "#555555",
}

SEV_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "NONE":     4,
}


# ──────────────────────────────────────────────────────────────────────────────
# State
# ──────────────────────────────────────────────────────────────────────────────

_cache: TTLLRUCache[dict] = TTLLRUCache(maxsize=500, ttl_seconds=600)
_last_request_time: float = 0.0
_locks: dict[int, asyncio.Lock] = {}


def _nvd_lock() -> asyncio.Lock:
    """One spacing lock per event loop (asyncio locks are loop-bound)."""
    loop = asyncio.get_running_loop()
    lock = _locks.get(id(loop))
    if lock is None:
        _locks.clear()               # drop locks of loops that are gone
        lock = _locks[id(loop)] = asyncio.Lock()
    return lock


def _api_key() -> Optional[str]:
    return os.getenv("NVD_API_KEY", "").strip() or None


def _request_delay() -> float:
    return NVD_REQUEST_DELAY_KEY if _api_key() else NVD_REQUEST_DELAY


def _make_client() -> httpx.AsyncClient:
    """Factory (patched in tests with an ``httpx.MockTransport``)."""
    return httpx.AsyncClient(timeout=REQUEST_TIMEOUT)


# ──────────────────────────────────────────────────────────────────────────────
# NVD HTTP layer with exponential back-off
# ──────────────────────────────────────────────────────────────────────────────

def _jittered_wait(attempt: int) -> float:
    """Return a jittered exponential back-off delay (seconds)."""
    base   = min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_MAX)
    jitter = base * _BACKOFF_JITTER
    return base + random.uniform(-jitter, jitter)


def parse_retry_after(value: Optional[str], now: Optional[datetime] = None) -> Optional[float]:
    """
    Seconds to wait from a ``Retry-After`` header (delta-seconds or
    HTTP-date).  Returns None when absent or unparseable.
    """
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return max(0.0, (when - now).total_seconds())


async def _nvd_request(params: dict) -> Optional[dict]:
    """
    Execute one NVD API query, honouring the rate limit and retrying on
    transient failures.

    Returns the raw NVD JSON on success, ``{"_error": "rate_limited", ...}``
    when retries are exhausted by 429s, or None on unrecoverable errors.
    """
    global _last_request_time
    headers = {"User-Agent": "LukitaPort Security Audit", "Accept": "application/json"}
    if key := _api_key():
        headers["apiKey"] = key

    for attempt in range(_MAX_RETRIES):
        resp: Optional[httpx.Response] = None
        transport_error: Optional[Exception] = None

        # ── Spacing lock: held only for the request itself ───────────────────
        async with _nvd_lock():
            elapsed = time.monotonic() - _last_request_time
            delay   = _request_delay()
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)
            try:
                async with _make_client() as client:
                    resp = await client.get(NVD_API_BASE, params=params, headers=headers)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                transport_error = exc
            finally:
                _last_request_time = time.monotonic()

        last_attempt = attempt == _MAX_RETRIES - 1

        # ── Outcome handling (lock released: back-off never blocks others) ───
        if transport_error is not None:
            if last_attempt:
                logger.error("nvd_unreachable", params=params, error=str(transport_error))
                return None
            wait = _jittered_wait(attempt)
            logger.warning("nvd_transient_error", attempt=attempt,
                           error=str(transport_error), wait_seconds=round(wait, 1))
            await asyncio.sleep(wait)
            continue

        assert resp is not None
        status = resp.status_code

        if status == 404:
            return {"totalResults": 0, "vulnerabilities": []}

        if status == 429 or status >= 500:
            if last_attempt:
                if status == 429:
                    return {"_error": "rate_limited", "totalResults": 0, "vulnerabilities": []}
                logger.error("nvd_http_error", status=status)
                return None
            retry_after = parse_retry_after(resp.headers.get("Retry-After"))
            wait = min(retry_after if retry_after is not None else _jittered_wait(attempt), _BACKOFF_MAX)
            logger.warning("nvd_retry", status=status, attempt=attempt, wait_seconds=round(wait, 1))
            await asyncio.sleep(wait)
            continue

        if status >= 400:
            logger.error("nvd_http_error", status=status)
            return None

        try:
            return resp.json()
        except ValueError as exc:
            logger.error("nvd_invalid_json", error=str(exc))
            return None

    return None  # pragma: no cover — loop always returns


# ──────────────────────────────────────────────────────────────────────────────
# CVE parsing
# ──────────────────────────────────────────────────────────────────────────────

def _parse_cve(vuln: dict) -> dict:
    cve    = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    description  = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )

    cvss_score: Optional[float] = None
    severity                    = "NONE"
    metrics                     = cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            m = metrics[key]
            if isinstance(m, list) and m:
                cvss_data  = m[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity   = (
                    m[0].get("baseSeverity")
                    or cvss_data.get("baseSeverity")
                    or "NONE"
                ).upper()
                break

    return {
        "id":             cve_id,
        "description":    description[:300] + ("..." if len(description) > 300 else ""),
        "cvss_score":     cvss_score,
        "severity":       severity,
        "severity_color": SEVERITY_COLORS.get(severity, "#555"),
        "published":      cve.get("published", "")[:10],
        "references":     [
            r.get("url", "")
            for r in cve.get("references", [])[:3]
            if r.get("url")
        ],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


# ──────────────────────────────────────────────────────────────────────────────
# CPE helpers
# ──────────────────────────────────────────────────────────────────────────────

def cpe_to_23(cpe: str) -> Optional[str]:
    """
    Convert an nmap CPE (2.2 URI ``cpe:/a:vendor:product:version`` or a
    2.3 string) into a CPE 2.3 prefix usable as NVD ``virtualMatchString``.

    Returns None unless vendor, product *and* version are present — without
    a version the match would cover every release and return noise.
    """
    cpe = (cpe or "").strip()
    if cpe.startswith("cpe:2.3:"):
        parts = cpe[len("cpe:2.3:"):].split(":")
    elif cpe.startswith("cpe:/"):
        parts = cpe[len("cpe:/"):].split(":")
    else:
        return None
    parts = [p for p in parts[:4]]
    if len(parts) < 4 or parts[0] not in ("a", "o", "h"):
        return None
    if not all(parts[1:4]) or parts[3] in ("*", "-"):
        return None
    return "cpe:2.3:" + ":".join(p.lower() for p in parts)


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def _empty(error: Optional[str], keyword: str) -> dict:
    return {"cves": [], "total": 0, "error": error, "keyword_used": keyword}


async def lookup_cves(
    service:     str,
    version:     str = "",
    max_results: int = 5,
    cpe:         Optional[str] = None,
) -> dict:
    """
    Look up CVEs by CPE (preferred, when ``cpe`` carries a version) or by
    keyword ``"<service> <version>"``.
    """
    cpe23 = cpe_to_23(cpe) if cpe else None
    if cpe23:
        query_desc = cpe23
        params     = {"virtualMatchString": cpe23}
    else:
        keyword = f"{service} {version}".strip() if version else (service or "").strip()
        if not keyword:
            return _empty("No keyword provided", "")
        query_desc = keyword
        params     = {"keywordSearch": keyword}
    params = {**params, "resultsPerPage": max_results, "startIndex": 0}

    cache_key = f"{query_desc.lower()}|{max_results}"
    cached    = _cache.get(cache_key)
    if cached is not None:
        logger.debug("cve_cache_hit", query=query_desc)
        return {**cached, "cached": True}

    logger.info("cve_lookup_start", query=query_desc, max_results=max_results)
    data = await _nvd_request(params)

    if data is None:
        return _empty("NVD API unavailable", query_desc)
    if data.get("_error") == "rate_limited":
        return _empty("NVD rate limit exceeded — please retry in ~30 s.", query_desc)

    cves = sorted(
        [_parse_cve(v) for v in data.get("vulnerabilities", [])[:max_results]],
        key=lambda c: SEV_ORDER.get(c["severity"], 9),
    )
    result = {
        "cves":         cves,
        "total":        data.get("totalResults", 0),
        "error":        None,
        "keyword_used": query_desc,
        "cached":       False,
    }
    _cache.set(cache_key, result)
    logger.info("cve_lookup_done", query=query_desc, total=result["total"], returned=len(cves))
    return result


SKIP_REASON = "No product/version known for this service — run fingerprinting first."


async def lookup_cves_for_ports(versions: dict) -> dict:
    """
    ``versions`` maps port → ``{"name", "product", "version", "cpe"}``.

    Queries by CPE when available, else by ``"<product> <version>"``; ports
    with neither a usable CPE nor product+version are reported as skipped.
    Invalid port keys are ignored.
    """
    results: dict[int, dict] = {}
    for port_key, info in versions.items():
        try:
            port = int(port_key)
        except (TypeError, ValueError):
            continue
        if not isinstance(info, dict):
            continue
        product = (info.get("product") or "").strip()
        version = (info.get("version") or "").strip()
        cpe     = (info.get("cpe") or "").strip()

        if cpe_to_23(cpe):
            result = await lookup_cves(product or info.get("name") or "", version, cpe=cpe)
        elif product and version:
            result = await lookup_cves(product, version)
        else:
            results[port] = {**_empty(SKIP_REASON, ""), "skipped": True}
            continue
        if result.get("cves") or result.get("error"):
            results[port] = result
    return results


def get_cache_stats() -> dict:
    return {"entries": _cache.size, "ttl_seconds": _cache.ttl_seconds, "maxsize": _cache.maxsize}
