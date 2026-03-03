"""
models.py
─────────
Pydantic V2 request / response models for every LukitaPort endpoint.

• Strict validation on all inputs (Field constraints, custom validators).
• Uniform envelope for all responses:  {ok, data, error, ts}.
• Type aliases keep annotations terse without sacrificing clarity.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Annotated, Any, Optional

from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
)

# ──────────────────────────────────────────────────────────────────────────────
# Re-usable type aliases
# ──────────────────────────────────────────────────────────────────────────────

Port        = Annotated[int,  Field(ge=1, le=65_535)]
Timeout     = Annotated[float, Field(ge=0.1, le=30.0)]
RiskLevel   = Annotated[str,  Field(pattern=r"^(high|medium|low|info)$")]
ScanMode    = Annotated[str,  Field(pattern=r"^(quick|full|custom)$")]
ScanProfile = Annotated[str,  Field(pattern=r"^(stealth|normal|aggressive)$")]

_HOSTNAME_RE = re.compile(
    r"^(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)){0,126}$"
)
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9\-]{1,63}$")


# ──────────────────────────────────────────────────────────────────────────────
# Shared validators
# ──────────────────────────────────────────────────────────────────────────────

def _validate_target_str(v: str) -> str:
    v = v.strip()
    if not v or len(v) > 253:
        raise ValueError("Target must be 1–253 characters.")
    # Try IPv4 / IPv6 first
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        pass
    # RFC 1123 hostname
    if _HOSTNAME_RE.match(v) and "." in v:
        return v
    raise ValueError(f"'{v}' is not a valid IPv4, IPv6, or RFC 1123 hostname.")


def _validate_domain_str(v: str) -> str:
    d = v.strip().lstrip("*.").lower()
    if not d or len(d) > 253 or "." not in d:
        raise ValueError("Domain must contain at least one dot (max 253 chars).")
    labels = d.split(".")
    if not all(_DOMAIN_LABEL_RE.match(lbl) for lbl in labels):
        raise ValueError(f"Domain '{d}' contains invalid characters.")
    return d


def _validate_cidr_str(v: str) -> str:
    try:
        ipaddress.ip_network(v.strip(), strict=False)
        return v.strip()
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR: {exc}") from exc


# ──────────────────────────────────────────────────────────────────────────────
# Generic response envelope
# ──────────────────────────────────────────────────────────────────────────────

class APIResponse(BaseModel):
    ok:    bool                = True
    data:  Optional[Any]       = None
    error: Optional[str]       = None
    ts:    datetime            = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def success(cls, data: Any) -> "APIResponse":
        return cls(ok=True, data=data)

    @classmethod
    def failure(cls, message: str) -> "APIResponse":
        return cls(ok=False, error=message)


# ──────────────────────────────────────────────────────────────────────────────
# /api/resolve
# ──────────────────────────────────────────────────────────────────────────────

class ResolveRequest(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def check_target(cls, v: str) -> str:
        return _validate_target_str(v)


class ResolveResponse(BaseModel):
    input:    str
    ip:       Optional[str]
    hostname: Optional[str]
    resolved: bool
    error:    Optional[str]


# ──────────────────────────────────────────────────────────────────────────────
# /api/geoip
# ──────────────────────────────────────────────────────────────────────────────

class GeoIPResponse(BaseModel):
    ip:           str
    country:      str  = ""
    country_code: str  = ""
    region:       str  = ""
    city:         str  = ""
    isp:          str  = ""
    asn:          str  = ""
    org:          str  = ""
    error:        Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# /api/scan  (SSE stream — individual events, not a final model)
# ──────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:     str
    mode:       ScanMode    = "quick"
    profile:    ScanProfile = "normal"
    port_start: Port        = 1
    port_end:   Port        = 1024
    timeout:    Timeout     = 1.0

    @field_validator("target")
    @classmethod
    def check_target(cls, v: str) -> str:
        return _validate_target_str(v)

    @model_validator(mode="after")
    def port_range_order(self) -> "ScanRequest":
        if self.mode == "custom" and self.port_start > self.port_end:
            raise ValueError("port_start must be ≤ port_end.")
        return self


class PortResult(BaseModel):
    port:            int
    state:           str
    service:         str
    response_time_ms: Optional[float] = None
    banner:          Optional[str]    = None
    version:         Optional[str]    = None
    risk:            Optional[str]    = None
    # SSE progress fields
    progress:        Optional[float]  = None
    scanned:         Optional[int]    = None
    total:           Optional[int]    = None


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

class DiscoverRequest(BaseModel):
    cidr:      str
    max_hosts: Annotated[int, Field(ge=1, le=1024)] = 254

    @field_validator("cidr")
    @classmethod
    def check_cidr(cls, v: str) -> str:
        return _validate_cidr_str(v)


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
    issuer:     str           = ""
    not_before: str           = ""
    not_after:  str           = ""
    ip:         Optional[str] = None
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
    hostname:            str
    port:                int
    valid:               bool
    error:               Optional[str]         = None
    subject:             dict[str, str]        = {}
    issuer:              dict[str, str]        = {}
    not_before:          Optional[str]         = None
    not_after:           Optional[str]         = None
    days_until_expiry:   Optional[int]         = None
    expired:             bool                  = False
    expiring_soon:       bool                  = False
    sans:                list[str]             = []
    cipher:              Optional[str]         = None
    protocol:            Optional[str]         = None
    protocol_version:    Optional[str]         = None   # e.g. "TLSv1.3"
    bits:                Optional[int]         = None
    weak_cipher:         bool                  = False
    deprecated_protocol: bool                  = False
    self_signed:         bool                  = False
    grade:               str                   = "F"
    issues:              list[str]             = []
    tls_versions_offered: list[str]            = []


class SSLResponse(BaseModel):
    target:  str
    ip:      str
    results: dict[str, SSLResult]


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


# ──────────────────────────────────────────────────────────────────────────────
# /api/export  (PDF / Markdown)
# ──────────────────────────────────────────────────────────────────────────────

class ScanData(BaseModel):
    meta:    dict[str, Any]
    results: list[dict[str, Any]]
    summary: dict[str, Any]


class ExportRequest(BaseModel):
    scan:              ScanData
    audit:             Optional[dict[str, Any]] = None
    screenshot_target: Optional[str]            = None


# ──────────────────────────────────────────────────────────────────────────────
# /api/screenshot
# ──────────────────────────────────────────────────────────────────────────────

class ScreenshotCaptureRequest(BaseModel):
    target: str
    port:   Port = 80

    @field_validator("target")
    @classmethod
    def check_target(cls, v: str) -> str:
        return _validate_target_str(v)


class ScreenshotCaptureResponse(BaseModel):
    status: str
    target: str
    port:   int
