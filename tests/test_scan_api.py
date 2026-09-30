"""/api/scan over SSE: loopback end-to-end, validation, slow profile, errors."""

import json
import socket
import threading

import pytest

import main
import scanner


def _events(client, **params):
    with client.stream("GET", "/api/scan", params=params) as resp:
        return [json.loads(line.removeprefix("data: ")) for line in resp.iter_lines() if line]


@pytest.fixture
def loopback_listener():
    """A TCP listener on 127.0.0.1 in a background thread (TestClient's loop
    runs in another thread, so an asyncio server here would not be served)."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                conn.close()
            except OSError:
                continue

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield sock.getsockname()[1]
    stop.set()
    t.join(2)
    sock.close()


def test_loopback_scan_end_to_end(app_client, allow_private, loopback_listener):
    port = loopback_listener
    events = _events(app_client, target="127.0.0.1", mode="custom",
                     port_start=port, port_end=port, timeout=1)
    assert events[0]["type"] == "meta" and events[0]["ip"] == "127.0.0.1"
    assert events[1]["type"] == "port" and events[1]["state"] == "open"
    assert events[-1] == {"type": "done", "open_ports": 1, "total_scanned": 1}


def test_inverted_custom_range_is_rejected(app_client, allow_private):
    events = _events(app_client, target="127.0.0.1", mode="custom",
                     port_start=200, port_end=100)
    assert events == [{
        "error": "Invalid custom range: start port (200) is greater than end port (100).",
        "status": 422,
    }]


def test_slow_profile_is_accepted(app_client, allow_private, monkeypatch):
    seen = {}

    async def fake_stream(ip, ports, timeout, **kw):
        seen.update(kw)
        yield {"port": ports[0], "state": "closed", "service": "x",
               "progress": 100, "scanned": 1, "total": 1}

    monkeypatch.setattr(main, "scan_ports_stream", fake_stream)
    events = _events(app_client, target="127.0.0.1", profile="slow")
    assert events[0]["profile"] == "slow"
    assert seen["shuffle"] is True and seen["jitter"] == scanner.PROFILES["slow"]["jitter"]


def test_unknown_profile_is_rejected(app_client):
    assert app_client.get("/api/scan", params={"target": "127.0.0.1", "profile": "anon"}).status_code == 422


def test_resource_error_is_reported(app_client, allow_private, monkeypatch):
    async def exhausted(ip, ports, timeout, **kw):
        raise scanner.ScanResourceError("Local resources exhausted")
        yield  # pragma: no cover

    monkeypatch.setattr(main, "scan_ports_stream", exhausted)
    events = _events(app_client, target="127.0.0.1")
    assert events[-1] == {"error": "Local resources exhausted", "status": 503}


def test_scanner_generator_is_closed_when_stream_ends(app_client, allow_private, monkeypatch):
    closed = []

    async def tracked(ip, ports, timeout, **kw):
        try:
            for p in ports:
                yield {"port": p, "state": "closed", "service": "x",
                       "progress": 0, "scanned": 1, "total": len(ports)}
        finally:
            closed.append(True)

    monkeypatch.setattr(main, "scan_ports_stream", tracked)
    _events(app_client, target="127.0.0.1")
    assert closed == [True]
