"""
Fix 3: closed ports on Windows must be "closed", not "filtered".

Windows answers a RST to its SYN by retransmitting the SYN (~2 s) before
reporting "connection refused", so with a 1 s timeout closed ports looked
filtered.  The scanner disables those retransmissions per socket with
SIO_TCP_INITIAL_RTO.  On Linux the Windows behaviour is simulated; the last
test runs for real on the Windows CI job (closed loopback port).
"""

import asyncio
import socket
import struct
import sys
import time

import pytest

import scanner


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_initial_rto_payload_layout():
    # TCP_INITIAL_RTO_PARAMETERS {USHORT Rtt; UCHAR MaxSynRetransmissions} (4 bytes)
    payload = scanner.initial_rto_payload(1.0)
    assert len(payload) == 4
    assert struct.unpack("<HB", payload[:3]) == (1000, scanner.TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS)
    assert struct.unpack("<H", scanner.initial_rto_payload(0.0001)[:2])[0] == 1
    assert struct.unpack("<H", scanner.initial_rto_payload(500)[:2])[0] == 0xFFFE


@pytest.fixture
def windows(monkeypatch):
    """
    Pretend to run on Windows: a fake WSAIoctl records which sockets got
    SIO_TCP_INITIAL_RTO, and sock_connect behaves like Windows — a RST is
    reported at once only on those sockets, otherwise after ~2 s of SYN
    retransmissions.
    """
    monkeypatch.setattr(scanner, "_IS_WINDOWS", True)
    monkeypatch.setattr(scanner, "_initial_rto_supported", None)
    state = {"ioctl": [], "fixed": set(), "connected_before_ioctl": False, "ioctl_works": True}

    def fake_ioctl(sock, code, payload):
        try:
            sock.getpeername()
            state["connected_before_ioctl"] = True
        except OSError:
            pass
        if not state["ioctl_works"]:
            raise OSError(10045, "WSAEOPNOTSUPP")
        state["ioctl"].append((code, payload))
        state["fixed"].add(sock.fileno())

    monkeypatch.setattr(scanner, "_windows_ioctl", fake_ioctl)

    async def windows_like_sock_connect(sock, address):
        if sock.fileno() not in state["fixed"]:
            await asyncio.sleep(2.0)            # SYN retransmissions after the RST
        raise ConnectionRefusedError(10061, "WSAECONNREFUSED")

    state["sock_connect"] = windows_like_sock_connect
    return state


async def _probe(state, monkeypatch, timeout=1.0):
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "sock_connect", state["sock_connect"])
    t0 = time.monotonic()
    res = await scanner._scan_port_async("127.0.0.1", 9, timeout)
    return res, time.monotonic() - t0


async def test_closed_port_is_closed_with_the_fix(windows, monkeypatch):
    res, elapsed = await _probe(windows, monkeypatch)
    assert res["state"] == "closed"
    assert elapsed < 0.5
    assert windows["ioctl"] == [(scanner.SIO_TCP_INITIAL_RTO, scanner.initial_rto_payload(1.0))]
    assert windows["connected_before_ioctl"] is False       # applied before connect


async def test_without_the_fix_the_port_looks_filtered(windows, monkeypatch):
    # Reproduces the reported bug: nothing disables the retransmissions.
    monkeypatch.setattr(scanner, "_disable_syn_retransmissions", lambda sock, t: True)
    res, _ = await _probe(windows, monkeypatch)
    assert res["state"] == "filtered"


async def test_old_windows_without_ioctl_waits_for_the_refusal(windows, monkeypatch):
    windows["ioctl_works"] = False
    res, elapsed = await _probe(windows, monkeypatch)
    assert res["state"] == "closed"                       # grace period covers ~2 s
    assert 1.5 < elapsed < scanner.WINDOWS_REFUSAL_GRACE + 0.5
    assert scanner._initial_rto_supported is False       # not retried on every port


def test_errno_tables_include_windows_socket_errors():
    import errno
    for name in ("WSAECONNREFUSED", "WSAECONNRESET"):
        if hasattr(errno, name):
            assert getattr(errno, name) in scanner._REFUSED_ERRNOS
    for name in ("WSAEMFILE", "WSAENOBUFS"):
        if hasattr(errno, name):
            assert getattr(errno, name) in scanner._RESOURCE_ERRNOS


async def test_closed_loopback_port_is_closed_fast_on_this_os():
    """Real sockets.  On Windows this is the reported bug (runs in CI)."""
    port = _closed_port()
    t0 = time.monotonic()
    res = await scanner._scan_port_async("127.0.0.1", port, 1.0)
    assert res["state"] == "closed", res
    assert time.monotonic() - t0 < 0.9


async def test_open_port_still_detected_with_own_socket():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        res = await scanner._scan_port_async("127.0.0.1", port, 1.0)
    assert res["state"] == "open"


@pytest.mark.skipif(not socket.has_ipv6, reason="no IPv6")
async def test_ipv6_loopback_closed_port():
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
            port = s.getsockname()[1]
    except OSError:
        pytest.skip("::1 not available")
    res = await scanner._scan_port_async("::1", port, 1.0)
    assert res["state"] == "closed"


@pytest.mark.skipif(sys.platform != "win32", reason="real WSAIoctl only on Windows")
def test_real_windows_ioctl_is_supported():
    with socket.socket() as s:
        assert scanner._disable_syn_retransmissions(s, 1.0) is True
