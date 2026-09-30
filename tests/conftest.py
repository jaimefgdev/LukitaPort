"""
Shared test fixtures.

Network safety rule
───────────────────
LukitaPort is a port scanner.  Tests must NEVER touch external hosts or real
networks: only 127.0.0.1 / ::1 with servers started by the test itself, or
mocked sockets/subprocesses.  The autouse ``_loopback_only`` fixture enforces
this by making any non-loopback connect, DNS lookup or subprocess spawn fail
the test immediately.  Tests that need a subprocess must mock it explicitly.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import sys

import pytest

_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


class ExternalNetworkAccess(AssertionError):
    """Raised when a test tries to reach something other than loopback."""


def _is_loopback_host(host) -> bool:
    if host is None:
        return True                           # passive / bind lookups
    if isinstance(host, bytes):
        host = host.decode()
    host = str(host).split("%", 1)[0]         # strip IPv6 zone id
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _loopback_only(monkeypatch):
    real_connect    = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def _check_address(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            if not _is_loopback_host(address[0]):
                raise ExternalNetworkAccess(f"blocked connect to {address!r}")

    def guarded_connect(self, address):
        _check_address(self, address)
        return real_connect(self, address)

    def guarded_connect_ex(self, address):
        _check_address(self, address)
        return real_connect_ex(self, address)

    def guarded_getaddrinfo(host, *args, **kwargs):
        if not _is_loopback_host(host):
            raise ExternalNetworkAccess(f"blocked DNS lookup of {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    def blocked_resolver(host, *args, **kwargs):
        if not _is_loopback_host(host):
            raise ExternalNetworkAccess(f"blocked DNS lookup of {host!r}")
        raise socket.herror(1, "reverse lookups disabled in tests")

    def guarded_gethostbyname(host):
        if not _is_loopback_host(host):
            raise ExternalNetworkAccess(f"blocked DNS lookup of {host!r}")
        return "127.0.0.1" if host.lower() in _LOOPBACK_NAMES else host

    async def blocked_subprocess(*args, **kwargs):
        raise ExternalNetworkAccess(f"blocked subprocess {args!r}; mock it in the test")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", guarded_gethostbyname)
    monkeypatch.setattr(socket, "gethostbyaddr", blocked_resolver)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", blocked_subprocess)
    monkeypatch.setattr(asyncio, "create_subprocess_shell", blocked_subprocess)


TEST_TOKEN = "test-token-0123456789abcdef"


@pytest.fixture(autouse=True)
def _security_env(monkeypatch):
    """
    Deterministic security settings for every test: a known API token, the
    TestClient host allowed, no GeoIP, private IPs blocked, and fresh caches
    / limiter counters.  Tests may override the environment and call
    ``security.reset_settings()``.
    """
    import limits
    import security

    for var in (
        "LUKITA_HOST", "LUKITA_PORT", "LUKITA_ENABLE_ADMIN", "LUKITA_RATE_LIMIT",
        "LUKITA_MAX_BODY_BYTES", "LUKITA_GEOIP_DB", "LUKITA_GEOIP_ASN_DB",
        "LUKITA_MAX_SCANS", "LUKITA_MAX_NMAP", "LUKITA_MAX_SCREENSHOTS",
        "LUKITA_MAX_AUDITS", "LUKITA_MAX_SSL", "ALLOW_PRIVATE_IPS",
        "NVD_API_KEY", "LOG_LEVEL",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LUKITA_API_TOKEN", TEST_TOKEN)
    monkeypatch.setenv("LUKITA_ALLOWED_HOSTS", "testserver,127.0.0.1,localhost")
    security.reset_settings()
    for lim in (limits.scans, limits.nmap, limits.screenshots, limits.audits, limits.ssl_checks):
        lim._in_use = 0
    yield
    security.reset_settings()


@pytest.fixture
def setenv(monkeypatch):
    """Set environment variables and reload the cached settings."""
    import security

    def _set(**values):
        for key, value in values.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)
        security.reset_settings()
    return _set


@pytest.fixture
def allow_private(setenv):
    """Allow internal targets (needed to point the API at 127.0.0.1)."""
    setenv(ALLOW_PRIVATE_IPS="true")


def _make_client(monkeypatch, headers):
    from fastapi.testclient import TestClient

    monkeypatch.setitem(sys.modules, "playwright.async_api", None)
    import main

    return TestClient(main.app, headers=headers)


@pytest.fixture
def app_client(monkeypatch):
    """
    Authenticated FastAPI TestClient (Bearer token) with the full lifespan.

    Playwright is made unimportable so no Chromium is launched; the lifespan
    must degrade gracefully in that case.
    """
    with _make_client(monkeypatch, {"Authorization": f"Bearer {TEST_TOKEN}"}) as client:
        yield client


@pytest.fixture
def anon_client(monkeypatch):
    """TestClient without credentials."""
    with _make_client(monkeypatch, {}) as client:
        yield client
