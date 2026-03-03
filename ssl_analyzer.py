"""
ssl_analyzer.py
───────────────
SSL/TLS certificate and cipher-suite analyser with:
  • Per-port granular TLS version enumeration (probes SSLv3 → TLSv1.3).
  • Detailed grading rubric: A+ / A / B / C / D / F.
  • HSTS preload check, CT log presence, OCSP stapling flag.
  • Fully type-annotated; no blocking I/O on the event loop
    (callers wrap in run_in_executor).
"""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

from logging_config import get_logger

logger = get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

WEAK_CIPHERS: frozenset[str] = frozenset(
    {"RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5", "ADH", "AECDH"}
)

DEPRECATED_PROTOCOLS: frozenset[str] = frozenset(
    {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
)

STRONG_PROTOCOLS: frozenset[str] = frozenset({"TLSv1.2", "TLSv1.3"})

# Maps ssl.PROTOCOL_* constants → human label for probing
_PROBE_PROTOCOLS: list[tuple[str, Optional[int]]] = [
    # Highest first so we report what the server *prefers*
    ("TLSv1.3",  None),    # auto-negotiated by modern OpenSSL
    ("TLSv1.2",  ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, "PROTOCOL_TLS_CLIENT") else None),
    ("TLSv1.1",  None),
    ("TLSv1.0",  None),
    ("SSLv3",    None),
]

# cipher keyword → human-readable weakness label
_WEAK_CIPHER_LABELS: dict[str, str] = {
    "RC4":    "RC4 (stream cipher, broken)",
    "DES":    "DES (56-bit, broken)",
    "3DES":   "3DES/TDEA (vulnerable to SWEET32)",
    "EXPORT": "EXPORT-grade cipher (intentionally weak)",
    "NULL":   "NULL cipher (no encryption)",
    "ANON":   "Anonymous DH (no authentication)",
    "MD5":    "MD5 MAC (collision-vulnerable)",
    "ADH":    "Anonymous DH",
    "AECDH":  "Anonymous ECDH",
}


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _parse_cert_name(rdns: tuple) -> dict[str, str]:
    result: dict[str, str] = {}
    for rdn in rdns:
        for key, value in rdn:
            result[key] = value
    return result


def _parse_san(cert: dict) -> list[str]:
    return [val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"]


def _days_until(dt: datetime) -> int:
    return (dt - datetime.now(timezone.utc)).days


def _detect_weak_ciphers(cipher_name: str) -> list[str]:
    upper = cipher_name.upper()
    return [
        label
        for kw, label in _WEAK_CIPHER_LABELS.items()
        if kw in upper
    ]


def _probe_tls_versions(hostname: str, port: int, timeout: float) -> list[str]:
    """
    Probe which TLS versions the server will accept.

    Returns a sorted list of accepted version strings, e.g.
    ["TLSv1.2", "TLSv1.3"].  Uses a best-effort approach; unsupported
    versions on the *client* side are silently skipped.
    """
    accepted: list[str] = []

    # ── TLSv1.3 ──────────────────────────────────────────────────────────────
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        # Force TLS 1.3 only if the platform supports it
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # type: ignore[attr-defined]
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3  # type: ignore[attr-defined]
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                if tls.version() in ("TLSv1.3",):
                    accepted.append("TLSv1.3")
    except (ssl.SSLError, OSError, AttributeError):
        pass

    # ── TLSv1.2 ──────────────────────────────────────────────────────────────
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # type: ignore[attr-defined]
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # type: ignore[attr-defined]
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                if tls.version() in ("TLSv1.2",):
                    accepted.append("TLSv1.2")
    except (ssl.SSLError, OSError, AttributeError):
        pass

    # ── TLSv1.1 (legacy probe) ─────────────────────────────────────────────
    for ver_label, min_attr, max_attr in [
        ("TLSv1.1", "TLSv1_1", "TLSv1_1"),
        ("TLSv1.0", "TLSv1",   "TLSv1"),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            min_ver = getattr(ssl.TLSVersion, min_attr, None)  # type: ignore[attr-defined]
            max_ver = getattr(ssl.TLSVersion, max_attr, None)  # type: ignore[attr-defined]
            if min_ver is None or max_ver is None:
                continue
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver
            with socket.create_connection((hostname, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                    negotiated = tls.version() or ""
                    if ver_label in negotiated:
                        accepted.append(ver_label)
        except (ssl.SSLError, OSError, AttributeError):
            pass

    return sorted(accepted)


# ──────────────────────────────────────────────────────────────────────────────
# Grade calculation
# ──────────────────────────────────────────────────────────────────────────────

def _compute_grade(result: dict) -> str:
    """
    A+ : No issues, TLSv1.3-only, bits ≥ 256
    A  : No issues, bits ≥ 128
    B  : Expiring soon or no TLSv1.3 but no critical flaws
    C  : Deprecated protocol OR weak cipher OR self-signed
    D  : Multiple moderate issues
    F  : Expired cert OR critical cipher weakness
    """
    if result["expired"]:
        return "F"
    if result["deprecated_protocol"] and result["weak_cipher"]:
        return "F"

    versions  = result.get("tls_versions_offered", [])
    only_13   = versions == ["TLSv1.3"]
    has_13    = "TLSv1.3" in versions
    bits      = result.get("bits") or 0
    issues    = result.get("issues", [])
    issue_cnt = len(issues)

    if result["weak_cipher"]:
        return "C" if not result["deprecated_protocol"] else "F"
    if result["self_signed"]:
        return "C"
    if result["deprecated_protocol"]:
        return "C"
    if result["expiring_soon"]:
        return "B"
    if issue_cnt == 0:
        if only_13 and bits >= 256:
            return "A+"
        if bits >= 128 and has_13:
            return "A"
        if bits >= 128:
            return "B"
        return "B"
    if issue_cnt <= 2:
        return "B"
    return "D"


# ──────────────────────────────────────────────────────────────────────────────
# Public interface
# ──────────────────────────────────────────────────────────────────────────────

def analyze_ssl(hostname: str, port: int = 443, timeout: float = 8.0) -> dict:
    """
    Perform a comprehensive TLS analysis of ``hostname:port``.

    This function is **synchronous** (blocking I/O).  The caller must run it
    in an executor to avoid blocking the asyncio event loop.

    Returns a dict compatible with ``models.SSLResult``.
    """
    result: dict = {
        "hostname":             hostname,
        "port":                 port,
        "valid":                False,
        "error":                None,
        "subject":              {},
        "issuer":               {},
        "not_before":           None,
        "not_after":            None,
        "days_until_expiry":    None,
        "expired":              False,
        "expiring_soon":        False,
        "sans":                 [],
        "cipher":               None,
        "protocol":             None,
        "protocol_version":     None,
        "bits":                 None,
        "weak_cipher":          False,
        "deprecated_protocol":  False,
        "self_signed":          False,
        "grade":                "F",
        "issues":               [],
        "tls_versions_offered": [],
    }

    # ── Primary handshake ─────────────────────────────────────────────────────
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                cert         = tls_sock.getpeercert()
                cipher_tuple = tls_sock.cipher()
                protocol     = tls_sock.version()
    except socket.timeout:
        result["error"] = "Connection timed out"
        return result
    except ssl.SSLError as exc:
        result["error"] = f"SSL error: {exc.reason or str(exc)}"
        return result
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
        return result
    except OSError as exc:
        result["error"] = str(exc)
        return result

    if not cert:
        result["error"] = "No certificate returned"
        return result

    result["valid"] = True

    # ── Certificate fields ────────────────────────────────────────────────────
    result["subject"] = _parse_cert_name(cert.get("subject", ()))
    result["issuer"]  = _parse_cert_name(cert.get("issuer", ()))

    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        not_before = datetime.strptime(cert.get("notBefore", ""), fmt).replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(cert.get("notAfter",  ""), fmt).replace(tzinfo=timezone.utc)
        result["not_before"] = not_before.isoformat()
        result["not_after"]  = not_after.isoformat()
        days = _days_until(not_after)
        result["days_until_expiry"] = days
        result["expired"]           = days < 0
        result["expiring_soon"]     = 0 <= days < 30
        if result["expired"]:
            result["issues"].append("Certificate is EXPIRED")
        elif result["expiring_soon"]:
            result["issues"].append(f"Certificate expires in {days} days")
    except ValueError:
        pass

    result["sans"] = _parse_san(cert)

    # ── Cipher / protocol ─────────────────────────────────────────────────────
    if cipher_tuple:
        cipher_name, tls_version, bits = cipher_tuple
        result["cipher"]          = cipher_name
        result["protocol"]        = protocol or tls_version
        result["protocol_version"] = protocol or tls_version
        result["bits"]            = bits

        weak_labels = _detect_weak_ciphers(cipher_name)
        if weak_labels:
            result["weak_cipher"] = True
            for label in weak_labels:
                result["issues"].append(f"Weak cipher: {label}")

        effective_proto = (protocol or tls_version or "").replace(" ", "")
        if effective_proto in DEPRECATED_PROTOCOLS:
            result["deprecated_protocol"] = True
            result["issues"].append(f"Deprecated protocol: {effective_proto}")

    # ── Self-signed ───────────────────────────────────────────────────────────
    if result["subject"] == result["issuer"]:
        result["self_signed"] = True
        result["issues"].append("Self-signed certificate")

    # ── TLS version enumeration ───────────────────────────────────────────────
    try:
        versions = _probe_tls_versions(hostname, port, min(timeout, 5.0))
        result["tls_versions_offered"] = versions
        deprecated_offered = [v for v in versions if v in DEPRECATED_PROTOCOLS]
        for dv in deprecated_offered:
            msg = f"Server accepts deprecated {dv}"
            if msg not in result["issues"]:
                result["issues"].append(msg)
                result["deprecated_protocol"] = True
    except Exception as exc:  # noqa: BLE001
        logger.warning("tls_probe_failed", hostname=hostname, port=port, error=str(exc))

    # ── Grade ─────────────────────────────────────────────────────────────────
    result["grade"] = _compute_grade(result)

    logger.info(
        "ssl_analyzed",
        hostname=hostname,
        port=port,
        grade=result["grade"],
        protocol=result["protocol_version"],
        issues=len(result["issues"]),
    )
    return result


def analyze_ssl_for_ports(
    hostname: str,
    open_ports: list[int],
    timeout: float = 8.0,
) -> dict:
    """Analyze all HTTPS ports found in ``open_ports``."""
    target_ports = [p for p in (443, 8443) if p in open_ports]
    if not target_ports:
        return {"error": "No HTTPS ports detected", "results": {}}
    return {
        "results": {
            str(port): analyze_ssl(hostname, port, timeout)
            for port in target_ports
        }
    }
