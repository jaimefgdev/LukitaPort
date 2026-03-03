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
"evil.example.com" whose A record resolves to "10.0.0.1".  By resolving first
and then checking the IP we also defend against DNS-rebinding attacks.
"""

from __future__ import annotations

import ipaddress
import os
import socket

from logging_config import get_logger

logger = get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Runtime configuration
# ──────────────────────────────────────────────────────────────────────────────

def _allow_private_ips() -> bool:
    """
    Read ALLOW_PRIVATE_IPS from the environment on every call.

    Re-reading (rather than caching at import time) lets unit tests patch
    ``os.environ`` without reloading the module.
    """
    return os.getenv("ALLOW_PRIVATE_IPS", "false").strip().lower() in ("1", "true", "yes")


# ──────────────────────────────────────────────────────────────────────────────
# SSRF classification helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_internal_address(ip_str: str) -> bool:
    """
    Return True if ``ip_str`` falls into any non-routable / internal range.

    Covers both IPv4 and IPv6.  The ``ipaddress`` stdlib correctly maps:

      IPv4
      ────
      127.0.0.0/8     → loopback
      10.0.0.0/8      ┐
      172.16.0.0/12   ├ private (RFC 1918)
      192.168.0.0/16  ┘
      169.254.0.0/16  → link-local  (incl. 169.254.169.254 AWS metadata)
      0.0.0.0/8       → unspecified
      240.0.0.0/4     → reserved
      224.0.0.0/4     → multicast

      IPv6
      ────
      ::1             → loopback
      fc00::/7        → unique local (private)
      fe80::/10       → link-local
      ff00::/8        → multicast
      ::/128          → unspecified
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        # Cannot parse → fail closed (treat as blocked)
        return True

    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


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

def is_valid_ip(target: str) -> bool:
    """
    Return True if ``target`` is a syntactically valid IPv4 address.

    Kept for backward compatibility with scanner.py which uses
    ``socket.inet_aton`` semantics.
    """
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


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

def resolve_target(target: str) -> dict:
    """
    Resolve ``target`` (IP or hostname) to a canonical IP address, then
    perform an SSRF check on the result.

    Returns
    -------
    dict with keys:
        input     : str            – original input string.
        ip        : str | None     – resolved IPv4/IPv6 string, or None.
        hostname  : str | None     – reverse-DNS result or original hostname.
        resolved  : bool           – True when a DNS lookup was performed.
        error     : str | None     – None on success.
                                     ``"ssrf_blocked"`` when the resolved IP is
                                     non-routable and ALLOW_PRIVATE_IPS is false.
                                     DNS error message string on resolution failure.

    The SSRF check is intentionally performed **after** DNS resolution.
    This ensures that hostnames like "internal.corp.example.com" that resolve
    to a private IP are caught (DNS-rebinding / confused-deputy defence).
    """
    target = target.strip()

    # ── Branch A: direct IP literal ──────────────────────────────────────────
    if is_valid_ip_any(target):
        hostname: str | None = None
        try:
            hostname = socket.gethostbyaddr(target)[0]
        except socket.herror:
            pass

        if is_ssrf_blocked(target):
            logger.warning(
                "ssrf_blocked",
                input=target,
                ip=target,
                allow_private=_allow_private_ips(),
            )
            return {
                "input":    target,
                "ip":       target,
                "hostname": hostname,
                "resolved": False,
                "error":    "ssrf_blocked",
            }

        return {
            "input":    target,
            "ip":       target,
            "hostname": hostname,
            "resolved": False,
            "error":    None,
        }

    # ── Branch B: hostname → DNS ──────────────────────────────────────────────
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        return {
            "input":    target,
            "ip":       None,
            "hostname": None,
            "resolved": False,
            "error":    str(exc),
        }

    # SSRF check on the *resolved* IP — catches DNS-rebinding
    if is_ssrf_blocked(ip):
        logger.warning(
            "ssrf_blocked",
            input=target,
            ip=ip,
            allow_private=_allow_private_ips(),
        )
        return {
            "input":    target,
            "ip":       ip,
            "hostname": target,
            "resolved": True,
            "error":    "ssrf_blocked",
        }

    return {
        "input":    target,
        "ip":       ip,
        "hostname": target,
        "resolved": True,
        "error":    None,
    }
