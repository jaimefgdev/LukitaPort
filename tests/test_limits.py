"""Point 7: concurrency caps, request size caps."""

import json

import pytest

import limits
import main


def test_slot_limiter_counts():
    lim = limits.SlotLimiter("x", "LUKITA_TEST_UNUSED", 2)
    assert lim.try_acquire() and lim.try_acquire()
    assert not lim.try_acquire()
    lim.release()
    assert lim.try_acquire()
    with pytest.raises(limits.Busy):
        lim.acquire()


def test_slot_limit_from_env(monkeypatch):
    monkeypatch.setenv("LUKITA_MAX_NMAP", "3")
    assert limits.nmap.limit == 3
    monkeypatch.setenv("LUKITA_MAX_NMAP", "garbage")
    assert limits.nmap.limit == 1


def test_nmap_busy_returns_429(app_client, monkeypatch, allow_private):
    async def never(*a, **k):
        pytest.fail("nmap must not run while busy")

    monkeypatch.setattr(main, "run_nmap", never)
    limits.nmap.acquire()
    resp = app_client.get("/api/fingerprint", params={"target": "127.0.0.1", "ports": "22"})
    assert resp.status_code == 429
    assert resp.json()["error"] == "busy"


def test_nmap_slot_released_after_run(app_client, monkeypatch, allow_private):
    async def fake_nmap(ip, ports, timeout):
        assert limits.nmap.in_use == 1
        return {}

    monkeypatch.setattr(main, "run_nmap", fake_nmap)
    resp = app_client.get("/api/fingerprint", params={"target": "127.0.0.1", "ports": "22,22,80"})
    assert resp.status_code == 200
    assert limits.nmap.in_use == 0


def test_fingerprint_port_cap(app_client, allow_private):
    ports = ",".join(str(p) for p in range(1, limits.MAX_FINGERPRINT_PORTS + 2))
    resp = app_client.get("/api/fingerprint", params={"target": "127.0.0.1", "ports": ports})
    assert resp.status_code == 400


def test_scan_busy_emits_429_event(app_client, allow_private):
    for _ in range(limits.scans.limit):
        limits.scans.acquire()
    with app_client.stream("GET", "/api/scan", params={"target": "127.0.0.1"}) as resp:
        event = json.loads(next(resp.iter_lines()).removeprefix("data: "))
    assert event["status"] == 429


def test_scan_releases_slot(app_client, monkeypatch, allow_private):
    async def fake_stream(ip, ports, timeout, **kw):
        yield {"port": 1, "state": "closed", "service": "x", "progress": 100,
               "scanned": 1, "total": 1}

    monkeypatch.setattr(main, "scan_ports_stream", fake_stream)
    with app_client.stream("GET", "/api/scan", params={"target": "127.0.0.1"}) as resp:
        lines = [l for l in resp.iter_lines() if l]
    assert json.loads(lines[-1].removeprefix("data: "))["type"] == "done"
    assert limits.scans.in_use == 0


def test_screenshot_busy_returns_429(app_client, allow_private):
    for _ in range(limits.screenshots.limit):
        limits.screenshots.acquire()
    resp = app_client.post("/api/screenshot/capture", params={"target": "127.0.0.1"})
    assert resp.status_code == 429


def test_cve_batch_is_bounded(app_client, monkeypatch):
    async def fake_lookup(payload):
        return {}

    monkeypatch.setattr(main, "lookup_cves_for_ports", fake_lookup)
    ok = {str(p): {"name": "ssh", "version": "1"} for p in range(1, limits.MAX_CVE_BATCH + 1)}
    assert app_client.post("/api/cve/batch", json=ok).status_code == 200

    too_many = {str(p): {"name": "ssh"} for p in range(1, limits.MAX_CVE_BATCH + 2)}
    assert app_client.post("/api/cve/batch", json=too_many).status_code == 422


@pytest.mark.parametrize("payload", [
    {"abc": {"name": "ssh"}},
    {"70000": {"name": "ssh"}},
    {"22": "not-an-object"},
    {"22": {"name": "x" * 101}},
    [1, 2, 3],
])
def test_cve_batch_rejects_bad_input(app_client, payload):
    assert app_client.post("/api/cve/batch", json=payload).status_code == 422


def test_cve_single_lengths(app_client):
    assert app_client.get("/api/cve", params={"service": "x" * 101}).status_code == 422


def test_export_result_count_cap(app_client):
    payload = {"scan": {"meta": {}, "summary": {},
                        "results": [{"port": 1}] * 65_536}}
    assert app_client.post("/api/export/md", json=payload).status_code == 422
