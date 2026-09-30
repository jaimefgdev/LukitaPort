"""
resolver.py
───────────
DNS resolution + SSRF protection for LukitaPort.

SSRF Protection
───────────────
After resolving any hostname to an IP, the resolved address is validated
against a blocklist of non-routable ranges:

  • Loopback        127.0.0.0/8, ::1
  • Private         10/8, 172.16/12, 192.168/16, fc00::/7
  • Link-local      169.254.0.0/16, fe80::/10   (incl. AWS metadata endpoint)
  • Reserved        0.0.0.0/8, 240.0.0.0/4, …
  • Multicast       224.0.0.0/4, ff00::/8

Environment variable
────────────────────
  ALLOW_PRIVATE_IPS=true   (default: false)

When set to "true" / "1" / "yes" (case-insensitive) all range checks are
bypassed.  Intended for local/educational use inside private networks.
Set it in your .env or docker-compose.yml:

    environment:
      - ALLOW_PRIVATE_IPS=true

When the env var is false (default) and a private IP is detected, the
returned dict will have:

    {"error": "ssrf_blocked", "ip": "<resolved-ip>", ...}

Callers (main.py) must check for this sentinel and return HTTP 403.

Design note — SSRF check happens AFTER DNS resolution
──────────────────────────────────────────────────────
Checking the hostname string alone is insufficient.  An attacker can register
"evil.example.com" whose A record resolves to "10.0.0.1".  So every address
the name resolves to is checked, and one of them is *pinned*: all later
connections (scan, nmap, audit, TLS, screenshot) go to that IP, with the
hostname sent only as Host header / SNI.  Resolving the name again later
would reopen the door to DNS rebinding (the second answer could be internal).
Redirects and page sub-resources are resolved and checked one by one
(``resolve_pinned``).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Optional

import settings
from logging_config import get_logger

logger = get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Runtime configuration
# ──────────────────────────────────────────────────────────────────────────────

def _allow_private_ips() -> bool:
    """ALLOW_PRIVATE_IPS from settings (re-read after ``reset_settings()``)."""
    return settings.get_settings().allow_private_ips


# ──────────────────────────────────────────────────────────────────────────────
# SSRF classification helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_internal_address(ip_str: str) -> bool:
    """
    Return True if ``ip_str`` is not a globally routable unicast address.

    Uses ``ipaddress``'s ``is_global`` (IANA special-purpose registries), so
    besides loopback, RFC 1918, link-local (incl. 169.254.169.254 cloud
    metadata), unspecified and reserved space it also covers CGNAT
    (100.64/10), benchmarking, documentation and similar ranges.  Multicast
    is blocked explicitly.  IPv4-mapped IPv6 (``::ffff:127.0.0.1``) is
    unwrapped first so it cannot smuggle an internal IPv4 address.
    """
    try:
        addr = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        # Cannot parse → fail closed (treat as blocked)
        return True

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    return (not addr.is_global) or addr.is_multicast


def is_ssrf_blocked(ip_str: str) -> bool:
    """
    Return True when this IP should be rejected with HTTP 403.

    Logic:
      • ALLOW_PRIVATE_IPS=true  → always False (never blocked)
      • otherwise               → True iff the address is internal/non-routable
    """
    if _allow_private_ips():
        return False
    return _is_internal_address(ip_str)


# ──────────────────────────────────────────────────────────────────────────────
# Low-level IP validation helpers
# ──────────────────────────────────────────────────────────────────────────────

def is_valid_ip_any(target: str) -> bool:
    """Return True for any valid IPv4 **or** IPv6 address string."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Public resolution function
# ──────────────────────────────────────────────────────────────────────────────

REVERSE_DNS_TIMEOUT = 1.0


async def reverse_lookup(ip: str, timeout: float = REVERSE_DNS_TIMEOUT) -> Optional[str]:
    """PTR name for ``ip`` (display only), or None on failure/timeout."""
    loop = asyncio.get_running_loop()
    try:
        name, _, _ = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout,
        )
        return name
    except (TimeoutError, OSError):
        return None


async def resolve_target(target: str, reverse_dns: bool = False) -> dict:
    """
    Resolve ``target`` (IP or hostname) to a canonical IP address, then
    perform an SSRF check on the result.  Never blocks the event loop.

    Returns
    -------
    dict with keys:
        input     : str            – original input string.
        ip        : str | None     – pinned IPv4/IPv6 address, or None.
        hostname  : str | None     – the hostname for hostname targets,
                                     None for IP literals.
        ptr       : str | None     – reverse-DNS name, only when
                                     ``reverse_dns`` is True (display only;
                                     never used to connect).
        resolved  : bool           – True when a DNS lookup was performed.
        addresses : list[str]      – every address the name resolved to.
        error     : str | None     – None on success.
                                     ``"ssrf_blocked"`` when a resolved IP is
                                     non-routable and ALLOW_PRIVATE_IPS is false.
                                     DNS error message string on resolution failure.

    The SSRF check is intentionally performed **after** DNS resolution.
    This ensures that hostnames like "internal.corp.example.com" that resolve
    to a private IP are caught (DNS-rebinding / confused-deputy defence).
    """
    target = target.strip()

    # ── Branch A: direct IP literal ──────────────────────────────────────────
    if is_valid_ip_any(target):
        ptr = await reverse_lookup(target) if reverse_dns else None
        literal_blocked = is_ssrf_blocked(target)
        if literal_blocked:
            logger.warning(
                "ssrf_blocked",
                input=target,
                ip=target,
                allow_private=_allow_private_ips(),
            )
        return {
            "input":     target,
            "ip":        target,
            "hostname":  None,
            "ptr":       ptr,
            "resolved":  False,
            "error":     "ssrf_blocked" if literal_blocked else None,
            "addresses": [target],
        }

    # ── Branch B: hostname → DNS ──────────────────────────────────────────────
    loop = asyncio.get_running_loop()
    try:
        addresses = await loop.run_in_executor(None, lookup_addresses, target)
    except socket.gaierror as exc:
        return {
            "input":     target,
            "ip":        None,
            "hostname":  None,
            "ptr":       None,
            "resolved":  False,
            "error":     str(exc),
            "addresses": [],
        }
    if not addresses:
        return {
            "input":     target,
            "ip":        None,
            "hostname":  None,
            "ptr":       None,
            "resolved":  False,
            "error":     "no addresses found",
            "addresses": [],
        }

    # Every returned address must pass: a hostname with one public and one
    # internal record could otherwise reach the internal one later.  The
    # first address is *pinned* — callers must connect to ``ip`` (sending
    # the hostname only as Host/SNI) so DNS is never consulted again.
    blocked = [a for a in addresses if is_ssrf_blocked(a)]
    if blocked:
        logger.warning(
            "ssrf_blocked",
            input=target,
            ip=blocked[0],
            allow_private=_allow_private_ips(),
        )
    return {
        "input":     target,
        "ip":        blocked[0] if blocked else addresses[0],
        "hostname":  target,
        "ptr":       None,
        "resolved":  True,
        "error":     "ssrf_blocked" if blocked else None,
        "addresses": addresses,
    }


def lookup_addresses(host: str) -> list[str]:
    """
    Return every distinct address ``host`` resolves to (IPv4 and IPv6),
    preserving resolver order.  Raises ``socket.gaierror`` on failure.
    """
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for *_, sockaddr in infos:
        addr = str(sockaddr[0])
        if addr not in seen:
            seen.append(addr)
    return seen


class BlockedDestination(Exception):
    """A destination resolved to an address the SSRF policy forbids."""


async def resolve_pinned(host: str) -> str:
    """
    Resolve ``host`` without blocking the event loop, validate *all* of its
    addresses and return the one to connect to.

    Raises ``BlockedDestination`` if any address is internal (and private
    addresses are not allowed) or the name does not resolve.
    """
    host = host.strip("[]")
    if is_valid_ip_any(host):
        if is_ssrf_blocked(host):
            raise BlockedDestination(f"{host} is an internal address")
        return host
    loop = asyncio.get_running_loop()
    try:
        addresses = await loop.run_in_executor(None, lookup_addresses, host)
    except socket.gaierror as exc:
        raise BlockedDestination(f"cannot resolve {host}: {exc}") from exc
    if not addresses:
        raise BlockedDestination(f"cannot resolve {host}")
    for addr in addresses:
        if is_ssrf_blocked(addr):
            raise BlockedDestination(f"{host} resolves to internal address {addr}")
    return addresses[0]


def network_ssrf_blocked(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """True when any address of ``network`` is internal and not allowed."""
    if _allow_private_ips():
        return False
    return any(
        _is_internal_address(str(a))
        for a in (network.network_address, network.broadcast_address, *network.hosts())
    )
