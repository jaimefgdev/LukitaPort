"""The safety net itself: non-loopback access must fail the test."""

import asyncio
import socket

import pytest

from conftest import ExternalNetworkAccess


def test_connect_to_non_loopback_is_blocked():
    # 192.0.2.0/24 is TEST-NET-1 (documentation range); the guard raises
    # before any packet is sent.
    with socket.socket() as s, pytest.raises(ExternalNetworkAccess):
        s.connect(("192.0.2.1", 80))


def test_dns_lookup_of_external_name_is_blocked():
    with pytest.raises(ExternalNetworkAccess):
        socket.getaddrinfo("example.com", 80)
    with pytest.raises(ExternalNetworkAccess):
        socket.gethostbyname("example.com")


async def test_subprocesses_are_blocked():
    with pytest.raises(ExternalNetworkAccess):
        await asyncio.create_subprocess_exec("ping", "-c", "1", "127.0.0.1")


async def test_loopback_connections_are_allowed():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await writer.wait_closed()
