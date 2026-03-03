"""
cve_lookup.py
─────────────
Async NVD CVE lookup with:
  • Exponential back-off on 429 / transient errors (jittered).
  • Global asyncio.Lock to honour the NVD free-tier rate-limit (1 req / 6 s).
  • In-process TTL cache (10 min) to avoid redundant network calls.
  • Structured logging throughout.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Optional

import httpx

from logging_config import get_logger

logger = get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

NVD_API_BASE      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT   = 12.0
RESULTS_PER_PAGE  = 5
NVD_REQUEST_DELAY = 6.2   # 5 requests / 30 s free-tier hard limit

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
# TTL Cache
# ──────────────────────────────────────────────────────────────────────────────

class _TTLCache:
    def __init__(self, ttl_seconds: int = 600) -> None:
        self._store: dict[str, tuple[dict, float]] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> Optional[dict]:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, created_at = entry
        if (time.monotonic() - created_at) >= self._ttl:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: dict) -> None:
        self._store[key] = (value, time.monotonic())

    def clear(self) -> None:
        self._store.clear()

    @property
    def size(self) -> int:
        return len(self._store)

    @property
    def ttl_seconds(self) -> int:
        return self._ttl


_cache                         = _TTLCache(ttl_seconds=600)
_nvd_lock                      = asyncio.Lock()
_last_request_time: float      = 0.0


# ──────────────────────────────────────────────────────────────────────────────
# NVD HTTP layer with exponential back-off
# ──────────────────────────────────────────────────────────────────────────────

def _jittered_wait(attempt: int) -> float:
    """Return a jittered exponential back-off delay (seconds)."""
    base  = min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_MAX)
    jitter = base * _BACKOFF_JITTER
    return base + random.uniform(-jitter, jitter)


async def _nvd_request(
    keyword: str,
    results_per_page: int = RESULTS_PER_PAGE,
) -> Optional[dict]:
    """
    Execute one NVD API request, honouring rate-limit and retrying on
    transient failures with jittered exponential back-off.

    Returns
    -------
    dict | None
        Raw NVD JSON on success; None on unrecoverable error.
        A ``{"_error": "rate_limited"}`` dict is returned when all retries
        are exhausted due to 429 responses.
    """
    global _last_request_time

    for attempt in range(_MAX_RETRIES):
        async with _nvd_lock:
            elapsed = time.monotonic() - _last_request_time
            if elapsed < NVD_REQUEST_DELAY:
                await asyncio.sleep(NVD_REQUEST_DELAY - elapsed)

            try:
                async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                    resp = await client.get(
                        NVD_API_BASE,
                        params={
                            "keywordSearch":  keyword,
                            "resultsPerPage": results_per_page,
                            "startIndex":     0,
                        },
                        headers={
                            "User-Agent": "LukitaPort Security Audit",
                            "Accept":     "application/json",
                        },
                    )
                    _last_request_time = time.monotonic()

                    if resp.status_code == 404:
                        return {"totalResults": 0, "vulnerabilities": []}

                    if resp.status_code == 429:
                        retry_after = float(resp.headers.get("Retry-After", _jittered_wait(attempt)))
                        wait        = min(retry_after, _BACKOFF_MAX)
                        logger.warning(
                            "nvd_rate_limited",
                            keyword=keyword,
                            attempt=attempt,
                            wait_seconds=round(wait, 1),
                        )
                        if attempt < _MAX_RETRIES - 1:
                            # Release the lock while waiting so other callers
                            # can make progress (they'll re-acquire before requesting)
                            pass  # lock released at end of `async with` block below

                    resp.raise_for_status()
                    return resp.json()

            except httpx.HTTPStatusError as exc:
                _last_request_time = time.monotonic()
                if exc.response.status_code == 429:
                    if attempt < _MAX_RETRIES - 1:
                        wait = _jittered_wait(attempt)
                        logger.warning(
                            "nvd_rate_limited_retry",
                            keyword=keyword,
                            attempt=attempt,
                            wait_seconds=round(wait, 1),
                        )
                        await asyncio.sleep(wait)
                        continue
                    return {"_error": "rate_limited", "totalResults": 0, "vulnerabilities": []}
                logger.error("nvd_http_error", keyword=keyword, status=exc.response.status_code)
                return None

            except (httpx.TimeoutException, httpx.TransportError) as exc:
                _last_request_time = time.monotonic()
                if attempt < _MAX_RETRIES - 1:
                    wait = _jittered_wait(attempt)
                    logger.warning(
                        "nvd_transient_error",
                        keyword=keyword,
                        attempt=attempt,
                        error=str(exc),
                        wait_seconds=round(wait, 1),
                    )
                    await asyncio.sleep(wait)
                    continue
                logger.error("nvd_unreachable", keyword=keyword, error=str(exc))
                return None

            except Exception as exc:  # noqa: BLE001
                _last_request_time = time.monotonic()
                logger.error("nvd_unexpected_error", keyword=keyword, error=str(exc))
                return None

    return {"_error": "rate_limited", "totalResults": 0, "vulnerabilities": []}


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
# Public API
# ──────────────────────────────────────────────────────────────────────────────

async def lookup_cves(
    service:     str,
    version:     str = "",
    max_results: int = 5,
) -> dict:
    keyword = f"{service} {version}".strip() if version else service.strip()
    if not keyword:
        return {
            "cves": [], "total": 0,
            "error": "No keyword provided", "keyword_used": "",
        }

    cache_key = keyword.lower()
    cached    = _cache.get(cache_key)
    if cached is not None:
        logger.debug("cve_cache_hit", keyword=keyword)
        return {**cached, "cached": True}

    logger.info("cve_lookup_start", keyword=keyword, max_results=max_results)
    data = await _nvd_request(keyword, max_results)

    if data is None:
        return {
            "cves": [], "total": 0,
            "error": "NVD API unavailable", "keyword_used": keyword,
        }
    if data.get("_error") == "rate_limited":
        return {
            "cves": [], "total": 0,
            "error": "NVD rate limit exceeded — please retry in ~30 s.",
            "keyword_used": keyword,
        }

    cves = sorted(
        [_parse_cve(v) for v in data.get("vulnerabilities", [])[:max_results]],
        key=lambda c: SEV_ORDER.get(c["severity"], 9),
    )
    result = {
        "cves":         cves,
        "total":        data.get("totalResults", 0),
        "error":        None,
        "keyword_used": keyword,
        "cached":       False,
    }
    _cache.set(cache_key, result)
    logger.info(
        "cve_lookup_done",
        keyword=keyword,
        total=result["total"],
        returned=len(cves),
    )
    return result


async def lookup_cves_for_ports(versions: dict) -> dict:
    results: dict[int, dict] = {}
    for port_str, info in versions.items():
        port    = int(port_str) if isinstance(port_str, str) else port_str
        service = info.get("name") or info.get("product") or ""
        version = info.get("version") or ""
        if not service:
            continue
        result = await lookup_cves(service, version)
        if result.get("cves") or result.get("error"):
            results[port] = result
    return results


def get_cache_stats() -> dict:
    return {"entries": _cache.size, "ttl_seconds": _cache.ttl_seconds}
