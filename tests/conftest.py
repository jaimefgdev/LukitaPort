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


@pytest.fixture
def app_client(monkeypatch):
    """
    FastAPI TestClient with the full lifespan (startup + shutdown).

    Playwright is made unimportable so no Chromium is launched; the lifespan
    must degrade gracefully in that case.
    """
    from fastapi.testclient import TestClient

    monkeypatch.setitem(sys.modules, "playwright.async_api", None)
    import main

    with TestClient(main.app) as client:
        yield client
