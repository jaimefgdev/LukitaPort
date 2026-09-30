"""Point 11: GeoIP is off by default and only ever local."""

import pytest

import geoip
import main
import scan_service


@pytest.fixture
def resolved(monkeypatch):
    """Resolve targets without any DNS (not even reverse lookups)."""
    monkeypatch.setattr(main, "resolve_target", lambda t: {
        "input": t, "ip": t, "hostname": None, "resolved": False,
        "error": None, "addresses": [t],
    })


def test_disabled_by_default(app_client, resolved):
    assert app_client.get("/api/config").json()["geoip"] == {
        "enabled": False, "source": None, "asn": False,
    }
    resp = app_client.get("/api/geoip", params={"target": "8.8.8.8"})
    assert resp.json() == {"ip": "8.8.8.8", "enabled": False}


async def test_fetch_geoip_disabled_returns_empty():
    # The network guard would fail this test on any outbound request.
    assert await scan_service.fetch_geoip("8.8.8.8") == {}


class FakeReader:
    def __init__(self, data):
        self.data = data

    def get(self, ip):
        return self.data.get(ip)


def test_local_lookup(monkeypatch, tmp_path):
    city = tmp_path / "GeoLite2-City.mmdb"
    asn = tmp_path / "GeoLite2-ASN.mmdb"
    monkeypatch.setenv("LUKITA_GEOIP_DB", str(city))
    monkeypatch.setenv("LUKITA_GEOIP_ASN_DB", str(asn))
    readers = {
        str(city): FakeReader({"8.8.8.8": {
            "country": {"iso_code": "US", "names": {"en": "United States"}},
            "subdivisions": [{"names": {"en": "California"}}],
            "city": {"names": {"en": "Mountain View"}},
        }}),
        str(asn): FakeReader({"8.8.8.8": {
            "autonomous_system_number": 15169,
            "autonomous_system_organization": "GOOGLE",
        }}),
    }
    monkeypatch.setattr(geoip, "_open", lambda path: readers[path])

    assert geoip.lookup("8.8.8.8") == {
        "country": "United States", "country_code": "US", "region": "California",
        "city": "Mountain View", "asn": "AS15169", "org": "GOOGLE",
    }
    assert geoip.lookup("1.1.1.1") == {}
    st = geoip.status()
    assert st["enabled"] and "GeoLite2-City.mmdb" in st["source"] and st["asn"]


def test_broken_database_never_raises(monkeypatch):
    monkeypatch.setenv("LUKITA_GEOIP_DB", "/nonexistent.mmdb")
    assert geoip.lookup("8.8.8.8") == {}


def test_enabled_endpoint(app_client, monkeypatch, resolved):
    monkeypatch.setenv("LUKITA_GEOIP_DB", "/x.mmdb")
    monkeypatch.setattr(geoip, "lookup", lambda ip: {"country": "Testland"})
    resp = app_client.get("/api/geoip", params={"target": "8.8.8.8"})
    assert resp.json() == {"ip": "8.8.8.8", "enabled": True, "country": "Testland"}
