"""
models.py
─────────
Pydantic v2 models and validated types for the HTTP API.

• Input types (``TargetStr``, ``DomainStr``, ``DiscoverCidr``) carry their
  validation, so a bad value is rejected by FastAPI with HTTP 422 in the
  common error format before the handler runs.  These are the only copies of
  the validation rules.
• Response models are used as ``response_model`` so the OpenAPI schema
  documents what each endpoint returns and FastAPI validates it.
• ``ErrorResponse`` is the single error format:
  ``{"ok": false, "error": "<code>", "detail": "<message>"}``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Any, Optional

from pydantic import AfterValidator, BaseModel, Field, RootModel, model_validator

from limits import MAX_CVE_BATCH

# ──────────────────────────────────────────────────────────────────────────────
# Validation rules
# ──────────────────────────────────────────────────────────────────────────────

_HOSTNAME_RE = re.compile(
    r"^(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)){0,126}$"
)
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9\-]{1,63}$")

# Widest network /api/discover accepts: a /22 holds 1022 usable hosts, which
# matches the upper bound of ``max_hosts``.  IPv6 sweeps are rejected — a /64
# cannot be enumerated at all.
DISCOVER_MIN_IPV4_PREFIX = 22


def validate_target(v: str) -> str:
    """IPv4/IPv6 literal or RFC 1123 hostname with at least one dot."""
    v = v.strip()
    if not v or len(v) > 253:
        raise ValueError("Target must be 1–253 characters.")
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        pass
    if _HOSTNAME_RE.match(v) and "." in v:
        return v
    raise ValueError(f"'{v}' is not a valid IPv4, IPv6, or RFC 1123 hostname.")


def validate_domain(v: str) -> str:
    d = v.strip().lstrip("*.").lower()
    if not d or len(d) > 253 or "." not in d:
        raise ValueError("Domain must contain at least one dot (max 253 chars).")
    if not all(_DOMAIN_LABEL_RE.match(lbl) for lbl in d.split(".")):
        raise ValueError(f"Domain '{d}' contains invalid characters.")
    return d


def validate_discover_cidr(v: str) -> str:
    try:
        network = ipaddress.ip_network(v.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR: {exc}") from exc
    if network.version != 4:
        raise ValueError("Only IPv4 networks can be discovered.")
    if network.prefixlen < DISCOVER_MIN_IPV4_PREFIX:
        raise ValueError(
            f"Network too large (/{network.prefixlen}); "
            f"the widest allowed is /{DISCOVER_MIN_IPV4_PREFIX}."
        )
    return str(network)


def parse_ports(raw: str, max_ports: int) -> list[int]:
    """Comma-separated ports → de-duplicated list (order kept)."""
    items = [p.strip() for p in raw.split(",")]
    if len(items) > max_ports:
        raise ValueError(f"Too many ports (max {max_ports}).")
    result: list[int] = []
    for p in items:
        if not p.isdigit():
            raise ValueError(f"Invalid port value: '{p}'")
        port = int(p)
        if not 1 <= port <= 65_535:
            raise ValueError(f"Port {port} is out of range (1–65535).")
        if port not in result:
            result.append(port)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Re-usable types
# ──────────────────────────────────────────────────────────────────────────────

Port         = Annotated[int, Field(ge=1, le=65_535)]
TargetStr    = Annotated[str, Field(max_length=300), AfterValidator(validate_target)]
DomainStr    = Annotated[str, Field(max_length=300), AfterValidator(validate_domain)]
DiscoverCidr = Annotated[str, Field(max_length=64), AfterValidator(validate_discover_cidr)]


# ──────────────────────────────────────────────────────────────────────────────
# Errors
# ──────────────────────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    ok:     bool = False
    error:  str                                 # machine-readable code
    detail: str                                 # human-readable message
    errors: Optional[list[dict[str, Any]]] = None   # field errors (422 only)


# ──────────────────────────────────────────────────────────────────────────────
# /api/resolve, /api/geoip
# ──────────────────────────────────────────────────────────────────────────────

class ResolveResponse(BaseModel):
    input:     str
    ip:        Optional[str]
    hostname:  Optional[str]
    ptr:       Optional[str] = None
    resolved:  bool
    addresses: list[str] = []
    error:     Optional[str]


class GeoIPResponse(BaseModel):
    ip:           str
    enabled:      bool
    country:      Optional[str] = None
    country_code: Optional[str] = None
    region:       Optional[str] = None
    city:         Optional[str] = None
    asn:          Optional[str] = None
    org:          Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# /api/fingerprint
# ──────────────────────────────────────────────────────────────────────────────

class FingerprintResponse(BaseModel):
    ip:          str
    timeout_sec: int
    results:     dict[str, Any]


# ──────────────────────────────────────────────────────────────────────────────
# /api/discover
# ──────────────────────────────────────────────────────────────────────────────

class AliveHost(BaseModel):
    ip:     str
    alive:  bool
    rtt_ms: Optional[float] = None


class DiscoverResponse(BaseModel):
    cidr:        str
    total_hosts: int
    alive_count: int
    alive:       list[AliveHost]


# ──────────────────────────────────────────────────────────────────────────────
# /api/subdomains
# ──────────────────────────────────────────────────────────────────────────────

class SubdomainEntry(BaseModel):
    subdomain:  str
    issuer:     str            = ""
    not_before: str            = ""
    not_after:  str            = ""
    ip:         Optional[str]  = None
    resolves:   Optional[bool] = None


class SubdomainsResponse(BaseModel):
    domain:     str
    total:      int
    subdomains: list[SubdomainEntry]


# ──────────────────────────────────────────────────────────────────────────────
# /api/audit
# ──────────────────────────────────────────────────────────────────────────────

class HeaderEntry(BaseModel):
    header:         str
    label:          str
    description_en: str
    description_es: str
    severity:       str
    status:         str
    value:          Optional[str] = None
    example:        str           = ""


class HeadersAuditResult(BaseModel):
    url:         str
    status_code: Optional[int]         = None
    present:     list[HeaderEntry]     = []
    missing:     list[HeaderEntry]     = []
    dangerous:   list[dict[str, str]]  = []
    score:       int                   = 0
    grade:       str                   = "F"
    error:       Optional[str]         = None


class TechEntry(BaseModel):
    name:     str
    icon:     str
    category: str
    version:  Optional[str] = None


class TechAuditResult(BaseModel):
    url:          str
    status_code:  Optional[int]              = None
    technologies: list[TechEntry]            = []
    by_category:  dict[str, list[TechEntry]] = {}
    count:        int                        = 0
    generator:    str                        = ""
    error:        Optional[str]              = None


class PathEntry(BaseModel):
    path:         str
    label:        str
    severity:     str
    description:  str
    status_code:  int
    content_type: str           = ""
    size_bytes:   int           = 0
    url:          str           = ""
    accessible:   bool


class PathsAuditResult(BaseModel):
    base_url:     str
    found:        list[PathEntry] = []
    not_found:    int             = 0
    errors:       int             = 0
    high_count:   int             = 0
    medium_count: int             = 0
    total_found:  int             = 0


class AuditResponse(BaseModel):
    target:       str
    ip:           str
    headers:      HeadersAuditResult
    technologies: TechAuditResult
    paths:        PathsAuditResult


# ──────────────────────────────────────────────────────────────────────────────
# /api/ssl
# ──────────────────────────────────────────────────────────────────────────────

class SSLResult(BaseModel):
    hostname:              str
    port:                  int
    valid:                 bool
    trusted:               bool                  = False
    verify_error:          Optional[str]         = None
    error:                 Optional[str]         = None
    subject:               dict[str, str]        = {}
    issuer:                dict[str, str]        = {}
    not_before:            Optional[str]         = None
    not_after:             Optional[str]         = None
    days_until_expiry:     Optional[int]         = None
    expired:               bool                  = False
    expiring_soon:         bool                  = False
    sans:                  list[str]             = []
    cipher:                Optional[str]         = None
    protocol:              Optional[str]         = None
    protocol_version:      Optional[str]         = None   # e.g. "TLSv1.3"
    bits:                  Optional[int]         = None
    weak_cipher:           bool                  = False
    deprecated_protocol:   bool                  = False
    self_signed:           bool                  = False
    grade:                 str                   = "F"
    issues:                list[str]             = []
    tls_versions_offered:  list[str]             = []
    tls_versions_untested: list[str]             = []


class SSLResponse(BaseModel):
    target:  str
    ip:      str
    results: dict[str, SSLResult]
    error:   Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# /api/cve
# ──────────────────────────────────────────────────────────────────────────────

class CVEEntry(BaseModel):
    id:             str
    description:    str
    cvss_score:     Optional[float] = None
    severity:       str             = "NONE"
    severity_color: str             = "#555"
    published:      str             = ""
    references:     list[str]       = []
    nvd_url:        str             = ""


class CVELookupResponse(BaseModel):
    keyword_used: str
    total:        int
    cves:         list[CVEEntry]
    error:        Optional[str] = None
    cached:       bool          = False
    skipped:      bool          = False


class CVEServiceInfo(BaseModel):
    name:    str = Field("", max_length=100)
    product: str = Field("", max_length=100)
    version: str = Field("", max_length=100)
    cpe:     str = Field("", max_length=200)


class CVEBatchRequest(RootModel[dict[Port, CVEServiceInfo]]):
    """``{"<port>": {"name", "product", "version", "cpe"}, ...}`` — bounded size."""

    @model_validator(mode="after")
    def cap_size(self) -> CVEBatchRequest:
        if len(self.root) > MAX_CVE_BATCH:
            raise ValueError(f"At most {MAX_CVE_BATCH} ports per CVE batch.")
        return self


class CVEBatchResponse(BaseModel):
    results: dict[int, CVELookupResponse]


# ──────────────────────────────────────────────────────────────────────────────
# /api/auth
# ──────────────────────────────────────────────────────────────────────────────

class AuthRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=512)


class AuthStatus(BaseModel):
    authenticated: bool


# ──────────────────────────────────────────────────────────────────────────────
# /api/export  (PDF / Markdown)
# ──────────────────────────────────────────────────────────────────────────────

class ScanData(BaseModel):
    meta:    dict[str, Any]
    results: list[dict[str, Any]] = Field(..., max_length=65_535)
    summary: dict[str, Any]


class ExportRequest(BaseModel):
    scan:              ScanData
    audit:             Optional[dict[str, Any]] = None
    screenshot_target: Optional[str]            = Field(None, max_length=253)


# ──────────────────────────────────────────────────────────────────────────────
# /api/screenshot
# ──────────────────────────────────────────────────────────────────────────────

class ScreenshotCaptureResponse(BaseModel):
    status: str
    target: str
    port:   int


# ──────────────────────────────────────────────────────────────────────────────
# /api/health
# ──────────────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    ok: bool = True
