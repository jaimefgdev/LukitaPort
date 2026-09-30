"""Point 4: /api/discover must reject huge ranges and never enumerate them."""

import ipaddress

import pytest

import main
import scan_service


@pytest.fixture
def swept(monkeypatch):
    """Replace the real ping sweep; record which hosts would be pinged."""
    calls: list[list] = []

    async def fake_ping_sweep(hosts):
        calls.append(list(hosts))
        return [{"ip": str(hosts[0]), "alive": True, "rtt_ms": 0.1}]

    monkeypatch.setattr(main, "ping_sweep", fake_ping_sweep)
    return calls


@pytest.mark.parametrize("cidr", ["10.0.0.0/8", "127.0.0.0/21", "0.0.0.0/0"])
def test_too_wide_ipv4_is_rejected(app_client, swept, cidr):
    resp = app_client.get("/api/discover", params={"cidr": cidr})
    assert resp.status_code == 400
    assert "too large" in resp.json()["error"]
    assert swept == []


@pytest.mark.parametrize("cidr", ["::1/128", "fd00::/64", "::/0"])
def test_ipv6_is_rejected(app_client, swept, cidr):
    resp = app_client.get("/api/discover", params={"cidr": cidr})
    assert resp.status_code == 400
    assert swept == []


def test_internal_network_is_ssrf_blocked(app_client, swept):
    resp = app_client.get("/api/discover", params={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 403
    assert resp.json()["error"] == "ssrf_blocked"
    assert swept == []


def test_invalid_cidr(app_client, swept):
    assert app_client.get("/api/discover", params={"cidr": "nope"}).status_code == 400


def test_widest_allowed_network_is_capped_by_max_hosts(app_client, swept, allow_private):
    resp = app_client.get("/api/discover", params={"cidr": "127.0.0.0/22", "max_hosts": 5})
    assert resp.status_code == 200
    assert resp.json()["total_hosts"] == 5
    assert [str(h) for h in swept[0]] == [f"127.0.0.{i}" for i in range(1, 6)]


def test_validate_cidr_does_not_enumerate(monkeypatch):
    def explode(self):
        raise AssertionError("hosts() must not be called during validation")

    monkeypatch.setattr(ipaddress.IPv4Network, "hosts", explode)
    network, err = main._validate_cidr("127.0.0.0/24")
    assert err is None and network.prefixlen == 24


async def test_ping_sweep_sorts_numerically(monkeypatch):
    async def fake_ping_one(ip):
        return {"ip": ip, "alive": True, "rtt_ms": None}

    monkeypatch.setattr(scan_service, "_ping_one", fake_ping_one)
    hosts = [ipaddress.ip_address(f"127.0.0.{i}") for i in (10, 9, 100, 2)]
    alive = await scan_service.ping_sweep(hosts)
    assert [h["ip"] for h in alive] == ["127.0.0.2", "127.0.0.9", "127.0.0.10", "127.0.0.100"]
