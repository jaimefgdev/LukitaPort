"""
security.py
───────────
Access control and HTTP hardening for LukitaPort.

Threat model
────────────
LukitaPort drives network scans, so anybody who can reach its API can use
the host as a scanning proxy.  The defaults therefore assume a single local
operator:

• The server listens on 127.0.0.1 unless ``LUKITA_HOST`` says otherwise
  (see ``run.py``).
• Every ``/api/`` route requires the API token.  The token comes from
  ``LUKITA_API_TOKEN``; when it is unset and the server listens on loopback,
  a random token is generated at startup and printed in a login URL (the
  Jupyter approach).  Listening on any other interface without
  ``LUKITA_API_TOKEN`` is refused.
• The browser authenticates once (``POST /api/auth``) and receives an
  HttpOnly, SameSite=Strict session cookie, so other websites cannot drive
  the API (no CSRF) and EventSource works without custom headers.  API
  clients may send ``Authorization: Bearer <token>`` instead.
• Requests whose ``Host`` header is not in ``LUKITA_ALLOWED_HOSTS`` are
  rejected, which defeats DNS-rebinding attacks against the UI.
• ``/api/admin/*`` only exists when ``LUKITA_ENABLE_ADMIN=true``.

Environment variables
─────────────────────
  LUKITA_API_TOKEN       API token (≥ 16 chars).  Mandatory off-loopback.
  LUKITA_HOST            Interface run.py binds to (default 127.0.0.1).
  LUKITA_ALLOWED_HOSTS   Comma-separated Host header allow-list
                         (default: 127.0.0.1,localhost,::1 + LUKITA_HOST).
  LUKITA_ENABLE_ADMIN    "true" to expose /api/admin/* (default false).
  LUKITA_RATE_LIMIT      Max /api/ requests per client per minute (default 120).
  LUKITA_MAX_BODY_BYTES  Max request body size (default 5 MiB).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from logging_config import get_logger

logger = get_logger(__name__)

SESSION_COOKIE   = "lukita_session"
MIN_TOKEN_LENGTH = 16
_TRUE            = ("1", "true", "yes", "on")

# Paths under /api/ reachable without credentials.
_AUTH_EXEMPT = frozenset({"/api/auth", "/api/auth/status"})


# ──────────────────────────────────────────────────────────────────────────────
# Settings
# ──────────────────────────────────────────────────────────────────────────────

def is_loopback_host(host: Optional[str]) -> bool:
    """True for loopback IP literals and ``localhost``; False otherwise."""
    if not host:
        return False
    host = host.strip().strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ConfigurationError(RuntimeError):
    """Raised when the security configuration is unsafe or invalid."""


@dataclass
class SecuritySettings:
    token:             str
    token_from_env:    bool
    bind_host:         str
    allowed_hosts:     frozenset[str]
    enable_admin:      bool
    rate_limit:        int
    max_body_bytes:    int
    _session_value:    str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._session_value = hmac.new(
            self.token.encode(), b"lukita-session-v1", hashlib.sha256,
        ).hexdigest()

    # ── Credential checks ─────────────────────────────────────────────────────

    def token_matches(self, candidate: str) -> bool:
        return hmac.compare_digest(candidate.encode(), self.token.encode())

    def session_value(self) -> str:
        return self._session_value

    def session_matches(self, cookie: str) -> bool:
        return hmac.compare_digest(cookie.encode(), self._session_value.encode())


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from exc
    if value < 1:
        raise ConfigurationError(f"{name} must be ≥ 1")
    return value


def load_settings() -> SecuritySettings:
    """Build settings from the environment; raise ConfigurationError if unsafe."""
    bind_host = os.getenv("LUKITA_HOST", "127.0.0.1").strip() or "127.0.0.1"
    env_token = os.getenv("LUKITA_API_TOKEN", "").strip()

    if env_token:
        if len(env_token) < MIN_TOKEN_LENGTH:
            raise ConfigurationError(
                f"LUKITA_API_TOKEN must be at least {MIN_TOKEN_LENGTH} characters."
            )
        token, from_env = env_token, True
    else:
        if not is_loopback_host(bind_host):
            raise ConfigurationError(
                f"LUKITA_API_TOKEN is required when listening on {bind_host!r} "
                "(a non-loopback interface)."
            )
        token, from_env = secrets.token_urlsafe(32), False

    hosts_raw = os.getenv("LUKITA_ALLOWED_HOSTS", "")
    allowed = {h.strip().lower().strip("[]") for h in hosts_raw.split(",") if h.strip()}
    if not allowed:
        allowed = {"127.0.0.1", "localhost", "::1"}
        if bind_host not in ("0.0.0.0", "::"):
            allowed.add(bind_host.lower().strip("[]"))

    return SecuritySettings(
        token=token,
        token_from_env=from_env,
        bind_host=bind_host,
        allowed_hosts=frozenset(allowed),
        enable_admin=os.getenv("LUKITA_ENABLE_ADMIN", "false").strip().lower() in _TRUE,
        rate_limit=_env_int("LUKITA_RATE_LIMIT", 120),
        max_body_bytes=_env_int("LUKITA_MAX_BODY_BYTES", 5 * 1024 * 1024),
    )


_settings: Optional[SecuritySettings] = None


def get_settings() -> SecuritySettings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def reset_settings() -> None:
    """Forget cached settings (tests, or after changing the environment)."""
    global _settings
    _settings = None
    _rate_limiter.reset()


# ──────────────────────────────────────────────────────────────────────────────
# Rate limiting
# ──────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """Sliding-window limiter: at most ``limit`` hits per ``window`` seconds per key."""

    def __init__(self, window: float = 60.0) -> None:
        self._window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int) -> bool:
        now  = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] >= self._window:
            hits.popleft()
        if len(hits) >= limit:
            return False
        hits.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()


_rate_limiter = RateLimiter()


# ──────────────────────────────────────────────────────────────────────────────
# Header helpers
# ──────────────────────────────────────────────────────────────────────────────

def _headers(scope: dict) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}


def _host_without_port(host_header: str) -> str:
    host = host_header.strip().lower()
    if host.startswith("["):                        # [::1]:8000
        return host[1:host.find("]")] if "]" in host else host
    if host.count(":") == 1:                        # example:8000
        return host.split(":", 1)[0]
    return host                                     # bare IPv6 or no port


def _cookie(headers: dict[str, str], name: str) -> Optional[str]:
    for part in headers.get("cookie", "").split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    return None


def is_authenticated(headers: dict[str, str], settings: SecuritySettings) -> bool:
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer ") and settings.token_matches(auth[7:].strip()):
        return True
    cookie = _cookie(headers, SESSION_COOKIE)
    return bool(cookie) and settings.session_matches(cookie)


# ──────────────────────────────────────────────────────────────────────────────
# Security headers (applied to every response)
# ──────────────────────────────────────────────────────────────────────────────

CONTENT_SECURITY_POLICY = "; ".join((
    "default-src 'self'",
    "script-src 'self'",
    # The UI renders many inline style="" attributes from templates.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
))

SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"content-security-policy", CONTENT_SECURITY_POLICY.encode()),
    (b"x-content-type-options",  b"nosniff"),
    (b"x-frame-options",         b"DENY"),
    (b"referrer-policy",         b"no-referrer"),
    (b"permissions-policy",      b"camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
)


# ──────────────────────────────────────────────────────────────────────────────
# ASGI middleware
# ──────────────────────────────────────────────────────────────────────────────

class SecurityMiddleware:
    """
    Pure-ASGI middleware enforcing, in order:

    1. Host header allow-list (anti DNS-rebinding)        → 400
    2. Refusal to serve off-loopback without an env token  → 503
    3. Cross-origin state-changing requests               → 403
    4. /api/admin/* disabled unless enabled               → 404
    5. Authentication on /api/*                            → 401
    6. Per-client rate limit on /api/*                     → 429
    7. Request body size limit                             → 413
    8. Security headers on every response
    """

    def __init__(self, app) -> None:  # noqa: ANN001
        self.app = app

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        headers  = _headers(scope)
        path     = scope.get("path", "")
        method   = scope.get("method", "GET").upper()

        async def send_with_headers(message) -> None:  # noqa: ANN001
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                message.setdefault("headers", [])
                message["headers"] = list(message["headers"]) + [
                    (k, v) for k, v in SECURITY_HEADERS if k not in existing
                ]
            await send(message)

        async def reject(status: int, error: str, detail: str) -> None:
            body = json.dumps({"ok": False, "error": error, "detail": detail}).encode()
            await send_with_headers({
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"cache-control", b"no-store"),
                ],
            })
            await send_with_headers({"type": "http.response.body", "body": body})

        # 1 ── Host allow-list ────────────────────────────────────────────────
        host = _host_without_port(headers.get("host", ""))
        if host not in settings.allowed_hosts:
            logger.warning("host_rejected", host=host)
            await reject(400, "invalid_host", "Host header not allowed (LUKITA_ALLOWED_HOSTS).")
            return

        # 2 ── Off-loopback exposure without an explicit token ───────────────
        server = scope.get("server") or (None, None)
        if not settings.token_from_env and not is_loopback_host(server[0]):
            await reject(
                503, "token_required",
                "Set LUKITA_API_TOKEN to serve on a non-loopback interface.",
            )
            return

        is_api = path == "/api" or path.startswith("/api/")

        # 3 ── Cross-origin writes (CSRF defence in depth) ────────────────────
        origin = headers.get("origin")
        if is_api and origin and method not in ("GET", "HEAD", "OPTIONS"):
            origin_host = _host_without_port(origin.split("://", 1)[-1])
            if origin_host != host:
                await reject(403, "cross_origin", "Cross-origin requests are not allowed.")
                return

        if is_api:
            # 4 ── Admin routes ───────────────────────────────────────────────
            if path.startswith("/api/admin") and not settings.enable_admin:
                await reject(404, "not_found", "Not Found")
                return

            # 5 ── Authentication ─────────────────────────────────────────────
            if path not in _AUTH_EXEMPT and not is_authenticated(headers, settings):
                await reject(401, "unauthorized", "Missing or invalid API token.")
                return

            # 6 ── Rate limit ─────────────────────────────────────────────────
            client = (scope.get("client") or ("unknown", 0))[0]
            limit  = settings.rate_limit
            # Token guessing gets a much smaller budget.
            key, budget = (f"auth:{client}", 10) if path == "/api/auth" else (client, limit)
            if not _rate_limiter.allow(key, budget):
                await reject(429, "rate_limited", "Too many requests, slow down.")
                return

        # 7 ── Body size limit ────────────────────────────────────────────────
        max_body = settings.max_body_bytes
        declared = headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > max_body:
            await reject(413, "payload_too_large", f"Request body exceeds {max_body} bytes.")
            return

        received = 0
        response_started = False
        rejected = False

        async def limited_receive():
            nonlocal received, rejected
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > max_body and not rejected:
                    rejected = True
                    if not response_started:
                        await reject(
                            413, "payload_too_large", f"Request body exceeds {max_body} bytes.",
                        )
                    # Make the application stop reading; whatever it tries
                    # to send afterwards is dropped by tracking_send.
                    return {"type": "http.disconnect"}
            return message

        async def tracking_send(message) -> None:  # noqa: ANN001
            nonlocal response_started
            if rejected:
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send_with_headers(message)

        await self.app(scope, limited_receive, tracking_send)


def login_url(settings: SecuritySettings, port: int) -> str:
    """URL that logs the browser in; the token travels in the fragment only."""
    host = settings.bind_host
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    if ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{port}/#token={settings.token}"
