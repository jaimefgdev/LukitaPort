"""
ssl_analyzer.py
───────────────
SSL/TLS certificate and cipher-suite analyser with:
  • Certificate parsing (subject, issuer, SANs, validity) and a separate
    verified handshake to report whether the chain is trusted.
  • Per-port TLS version enumeration (TLS 1.0 → 1.3; versions the local
    OpenSSL cannot offer are reported as untested).
  • Grading rubric: A+ / A / B / C / D / F.
  • Synchronous (blocking) I/O: callers run it in an executor.
"""

from __future__ import annotations

import ipaddress
import ssl
import socket
import warnings
from datetime import datetime, UTC
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID

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

# Attribute names match the keys ``ssl.SSLSocket.getpeercert()`` used to
# produce, which the frontend and report generators rely on.
_NAME_ATTRS: dict[x509.ObjectIdentifier, str] = {
    NameOID.COMMON_NAME:              "commonName",
    NameOID.ORGANIZATION_NAME:        "organizationName",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
    NameOID.COUNTRY_NAME:             "countryName",
    NameOID.STATE_OR_PROVINCE_NAME:   "stateOrProvinceName",
    NameOID.LOCALITY_NAME:            "localityName",
    NameOID.EMAIL_ADDRESS:            "emailAddress",
}


def _parse_cert_name(name: x509.Name) -> dict[str, str]:
    result: dict[str, str] = {}
    for attr in name:
        key = _NAME_ATTRS.get(attr.oid, attr.oid.dotted_string)
        value = attr.value
        result[key] = value if isinstance(value, str) else value.hex()
    return result


def _parse_san(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return ext.value.get_values_for_type(x509.DNSName)


def _verify_chain(
    hostname: str,
    port: int,
    timeout: float,
    cafile: Optional[str] = None,
    connect_host: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """
    Perform a second handshake with full certificate verification.

    Returns ``(trusted, reason)``.  ``trusted`` is True only when the chain
    validates against the system trust store (or ``cafile``) and, for
    hostname targets, the certificate matches the hostname.
    """
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        ipaddress.ip_address(hostname)
        ctx.check_hostname = False          # no hostname to match for IP targets
    except ValueError:
        pass
    try:
        with socket.create_connection((connect_host or hostname, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message or str(exc)
    except (ssl.SSLError, OSError) as exc:
        return False, str(exc)


def _days_until(dt: datetime) -> int:
    return (dt - datetime.now(UTC)).days


def _detect_weak_ciphers(cipher_name: str) -> list[str]:
    upper = cipher_name.upper()
    return [
        label
        for kw, label in _WEAK_CIPHER_LABELS.items()
        if kw in upper
    ]


# (label, TLSVersion attribute, ssl.HAS_* flag)
_PROBE_VERSIONS: tuple[tuple[str, str, str], ...] = (
    ("TLSv1.3", "TLSv1_3", "HAS_TLSv1_3"),
    ("TLSv1.2", "TLSv1_2", "HAS_TLSv1_2"),
    ("TLSv1.1", "TLSv1_1", "HAS_TLSv1_1"),
    ("TLSv1.0", "TLSv1",   "HAS_TLSv1"),
)
_LEGACY_VERSIONS = frozenset({"TLSv1.1", "TLSv1.0"})


def _client_can_probe(label: str, attr: str, has_flag: str) -> bool:
    return bool(getattr(ssl, has_flag, False)) and hasattr(ssl.TLSVersion, attr)


def _accepts_version(
    hostname: str,
    port: int,
    timeout: float,
    label: str,
    attr: str,
    connect_host: Optional[str],
) -> bool:
    version = getattr(ssl.TLSVersion, attr)
    with warnings.catch_warnings():
        # Pinning TLS 1.0/1.1 is deprecated in Python — which is exactly the
        # point of probing for it.
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        if label in _LEGACY_VERSIONS:
            # Modern OpenSSL refuses TLS < 1.2 at the default security level
            # regardless of what the server supports; drop to level 0 so
            # the probe reflects the *server*.
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
    try:
        with socket.create_connection((connect_host or hostname, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                return tls.version() == label.replace("TLSv1.0", "TLSv1")
    except (ssl.SSLError, OSError):
        return False


def _probe_tls_versions(
    hostname: str,
    port: int,
    timeout: float,
    connect_host: Optional[str] = None,
) -> tuple[list[str], list[str]]:
    """
    Probe which TLS versions (1.0–1.3) the server accepts, one handshake per
    version.

    Returns ``(accepted, untested)``: ``untested`` lists versions the local
    OpenSSL build cannot offer at all, so no conclusion is possible for them.
    SSLv2/SSLv3 are not probed (not available in any supported OpenSSL).
    """
    accepted: list[str] = []
    untested: list[str] = []
    for label, attr, has_flag in _PROBE_VERSIONS:
        if not _client_can_probe(label, attr, has_flag):
            untested.append(label)
            continue
        if _accepts_version(hostname, port, timeout, label, attr, connect_host):
            accepted.append(label)
    return sorted(accepted), untested


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

def analyze_ssl(
    hostname: str,
    port: int = 443,
    timeout: float = 8.0,
    cafile: Optional[str] = None,
    connect_host: Optional[str] = None,
) -> dict:
    """
    Perform a comprehensive TLS analysis of ``hostname:port``.

    This function is **synchronous** (blocking I/O).  The caller must run it
    in an executor to avoid blocking the asyncio event loop.

    ``connect_host`` is the SSRF-validated IP to connect to; ``hostname`` is
    then only used for SNI and certificate matching, so DNS is not consulted
    again (anti-rebinding).  Defaults to ``hostname``.

    ``valid`` means a certificate was retrieved and parsed; ``trusted``
    reports whether it also validates against the trust store (``cafile``
    overrides the system store, mainly for tests).

    Returns a dict compatible with ``models.SSLResult``.
    """
    result: dict = {
        "hostname":             hostname,
        "port":                 port,
        "valid":                False,
        "trusted":              False,
        "verify_error":         None,
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
        "tls_versions_untested": [],
    }

    # ── Primary handshake ─────────────────────────────────────────────────────
    # Verification is disabled so we can inspect untrusted/expired certs.
    # With CERT_NONE, getpeercert() returns an empty dict, so the DER form is
    # requested and parsed with ``cryptography`` instead.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        with socket.create_connection((connect_host or hostname, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                der          = tls_sock.getpeercert(binary_form=True)
                cipher_tuple = tls_sock.cipher()
                protocol     = tls_sock.version()
    except TimeoutError:
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

    if not der:
        result["error"] = "No certificate returned"
        return result

    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        result["error"] = f"Unparseable certificate: {exc}"
        return result

    result["valid"] = True

    # ── Certificate fields ────────────────────────────────────────────────────
    result["subject"] = _parse_cert_name(cert.subject)
    result["issuer"]  = _parse_cert_name(cert.issuer)

    not_before = cert.not_valid_before_utc
    not_after  = cert.not_valid_after_utc
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
    if cert.subject == cert.issuer:
        result["self_signed"] = True
        result["issues"].append("Self-signed certificate")

    # ── Chain / hostname verification ─────────────────────────────────────────
    trusted, reason = _verify_chain(hostname, port, timeout, cafile, connect_host)
    result["trusted"]      = trusted
    result["verify_error"] = reason
    # Self-signed and expired certs are already reported above.
    if not trusted and not result["self_signed"] and not result["expired"]:
        result["issues"].append(f"Certificate not trusted: {reason}")

    # ── TLS version enumeration ───────────────────────────────────────────────
    try:
        versions, untested = _probe_tls_versions(hostname, port, min(timeout, 5.0), connect_host)
        result["tls_versions_offered"]  = versions
        result["tls_versions_untested"] = untested
        deprecated_offered = [v for v in versions if v in DEPRECATED_PROTOCOLS]
        for dv in deprecated_offered:
            msg = f"Server accepts deprecated {dv}"
            if msg not in result["issues"]:
                result["issues"].append(msg)
                result["deprecated_protocol"] = True
    except Exception as exc:
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
    connect_host: Optional[str] = None,
) -> dict:
    """Analyze all HTTPS ports found in ``open_ports``."""
    target_ports = [p for p in (443, 8443) if p in open_ports]
    if not target_ports:
        return {"error": "No HTTPS ports detected", "results": {}}
    return {
        "results": {
            str(port): analyze_ssl(hostname, port, timeout, connect_host=connect_host)
            for port in target_ports
        }
    }
