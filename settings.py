"""
settings.py
───────────
Single source of truth for configuration (environment variables).

Values are parsed and validated once with pydantic-settings; an invalid
value (e.g. ``LUKITA_MAX_SCANS=abc``) makes startup fail with a clear error
instead of being silently replaced by a default.  Modules read settings via
``get_settings()``; tests change the environment and call
``reset_settings()``.

See ``.env.example`` for every variable and its default.
"""

from __future__ import annotations

from typing import Optional

from pydantic import Field, PositiveInt, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", populate_by_name=False)

    # ── Access control (security.py) ──────────────────────────────────────────
    api_token:      str         = Field("", validation_alias="LUKITA_API_TOKEN")
    host:           str         = Field("127.0.0.1", validation_alias="LUKITA_HOST")
    port:           int         = Field(8000, ge=1, le=65_535, validation_alias="LUKITA_PORT")
    allowed_hosts:  str         = Field("", validation_alias="LUKITA_ALLOWED_HOSTS")
    enable_admin:   bool        = Field(False, validation_alias="LUKITA_ENABLE_ADMIN")
    rate_limit:     PositiveInt = Field(120, validation_alias="LUKITA_RATE_LIMIT")
    max_body_bytes: PositiveInt = Field(5 * 1024 * 1024, validation_alias="LUKITA_MAX_BODY_BYTES")

    # ── Concurrency limits (limits.py) ────────────────────────────────────────
    max_scans:       PositiveInt = Field(2, validation_alias="LUKITA_MAX_SCANS")
    max_nmap:        PositiveInt = Field(1, validation_alias="LUKITA_MAX_NMAP")
    max_screenshots: PositiveInt = Field(2, validation_alias="LUKITA_MAX_SCREENSHOTS")
    max_audits:      PositiveInt = Field(2, validation_alias="LUKITA_MAX_AUDITS")
    max_ssl:         PositiveInt = Field(2, validation_alias="LUKITA_MAX_SSL")

    # ── SSRF (resolver.py) ────────────────────────────────────────────────────
    allow_private_ips: bool = Field(False, validation_alias="ALLOW_PRIVATE_IPS")

    # ── Integrations ──────────────────────────────────────────────────────────
    geoip_db:     Optional[str] = Field(None, validation_alias="LUKITA_GEOIP_DB")
    geoip_asn_db: Optional[str] = Field(None, validation_alias="LUKITA_GEOIP_ASN_DB")
    nvd_api_key:  Optional[str] = Field(None, validation_alias="NVD_API_KEY")

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = Field("INFO", validation_alias="LOG_LEVEL")

    @field_validator("api_token", "host", "allowed_hosts", mode="before")
    @classmethod
    def _strip(cls, v: object) -> object:
        return v.strip() if isinstance(v, str) else v

    @field_validator("geoip_db", "geoip_asn_db", "nvd_api_key", mode="before")
    @classmethod
    def _empty_is_none(cls, v: object) -> object:
        if isinstance(v, str):
            v = v.strip()
            return v or None
        return v

    @field_validator("log_level")
    @classmethod
    def _log_level(cls, v: str) -> str:
        v = v.strip().upper()
        if v not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError("must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
        return v


class SettingsError(RuntimeError):
    """The environment holds an invalid configuration value."""


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        try:
            _settings = Settings()
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
            )
            raise SettingsError(f"Invalid configuration — {problems}") from exc
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
