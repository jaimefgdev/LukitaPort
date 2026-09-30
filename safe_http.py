"""
safe_http.py
────────────
SSRF-safe outbound HTTP for the auditor and the screenshot proxy.

Guarantees
──────────
• Every hostname is resolved once per request chain with ``resolve_pinned``
  (all addresses validated against the SSRF policy) and the connection is
  made to that IP; the hostname travels only as ``Host`` header and TLS SNI.
  httpx never performs its own DNS lookup, so a rebinding DNS server cannot
  swap in an internal address between the check and the connection.
• Redirects are followed manually (httpx's automatic following is disabled)
  and each hop is re-validated, so ``302 Location: http://169.254.169.254/``
  is refused.
• Only http/https URLs are allowed.
• Response bodies are streamed and truncated at ``max_bytes``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from resolver import BlockedDestination, is_valid_ip_any, resolve_pinned

__all__ = ["BlockedDestination", "SafeResponse", "fetch", "make_client"]

DEFAULT_MAX_BYTES = 512 * 1024
REDIRECT_CODES    = frozenset({301, 302, 303, 307, 308})
USER_AGENT        = "Mozilla/5.0 (LukitaPort Security Audit)"


@dataclass
class SafeResponse:
    status:    int
    headers:   httpx.Headers
    body:      bytes
    url:       str            # final URL, with the original hostname
    truncated: bool = False

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def make_client(timeout: float = 6.0) -> httpx.AsyncClient:
    """Client for use with ``fetch``: no redirects, no TLS verification."""
    return httpx.AsyncClient(
        verify=False,               # auditing broken TLS is the point
        follow_redirects=False,     # redirects are validated hop by hop
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        limits=httpx.Limits(max_connections=40, max_keepalive_connections=10),
        trust_env=False,            # never route through an env proxy
    )


async def fetch(
    client:        httpx.AsyncClient,
    url:           str,
    *,
    method:        str = "GET",
    headers:       Optional[dict[str, str]] = None,
    content:       Optional[bytes] = None,
    pinned:        Optional[dict[str, str]] = None,
    max_redirects: int = 5,
    max_bytes:     int = DEFAULT_MAX_BYTES,
    timeout:       Optional[float] = None,
) -> SafeResponse:
    """
    Perform an SSRF-checked request.

    ``pinned`` maps hostnames that were already validated (e.g. the scan
    target) to the IP to use; it is updated with every host resolved along
    the redirect chain.  Raises ``BlockedDestination`` for forbidden
    destinations and ``httpx.HTTPError`` for transport errors.
    """
    pins    = pinned if pinned is not None else {}
    current = httpx.URL(url)

    for hop in range(max_redirects + 1):
        if current.scheme not in ("http", "https"):
            raise BlockedDestination(f"scheme {current.scheme!r} not allowed")
        host = current.host
        if not host:
            raise BlockedDestination("URL without host")
        ip = pins.get(host)
        if ip is None:
            ip = await resolve_pinned(host)
            pins[host] = ip

        req_headers = dict(headers or {})
        req_headers["Host"] = current.netloc.decode("ascii")
        extensions = {}
        if current.scheme == "https" and not is_valid_ip_any(host):
            extensions["sni_hostname"] = host

        request = client.build_request(
            method,
            current.copy_with(host=ip),
            headers=req_headers,
            content=content,
            extensions=extensions,
            timeout=timeout if timeout is not None else client.timeout,
        )
        response = await client.send(request, stream=True)
        try:
            body, truncated = await _read_limited(response, max_bytes)
        finally:
            await response.aclose()

        location = response.headers.get("location")
        if response.status_code in REDIRECT_CODES and location and hop < max_redirects:
            current = current.join(location)
            if response.status_code == 303 or (
                response.status_code in (301, 302) and method.upper() == "POST"
            ):
                method, content = "GET", None
            continue

        return SafeResponse(
            status=response.status_code,
            headers=response.headers,
            body=body,
            url=str(current),
            truncated=truncated,
        )

    raise AssertionError("unreachable")  # pragma: no cover


async def _read_limited(response: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        remaining = max_bytes - size
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            return b"".join(chunks), True
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks), False
