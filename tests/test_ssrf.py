"""Point 6: SSRF policy, all-address checks, pinning, discover, Chromium."""

import ipaddress
import json

import pytest

import auditor
import limits
import main
import resolver
import scan_service
from http_helpers import LoopbackHTTPServer

# Pure classification — no network involved.
INTERNAL = [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1",
    "169.254.169.254", "0.0.0.0", "224.0.0.1", "240.0.0.1", "192.0.2.10",
    "::1", "::", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1",
    "::ffff:10.0.0.1", "not-an-ip",
]
EXTERNAL = ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "::ffff:8.8.8.8"]


@pytest.mark.parametrize("ip", INTERNAL)
def test_internal_addresses_are_blocked(ip):
    assert resolver.is_ssrf_blocked(ip)


@pytest.mark.parametrize("ip", EXTERNAL)
def test_global_addresses_are_allowed(ip):
    assert not resolver.is_ssrf_blocked(ip)


def test_allow_private_ips_disables_policy(allow_private):
    assert not resolver.is_ssrf_blocked("127.0.0.1")


def test_hostname_with_any_internal_record_is_blocked(monkeypatch):
    monkeypatch.setattr(resolver, "lookup_addresses", lambda h: ["8.8.8.8", "10.0.0.5"])
    res = resolver.resolve_target("mixed.test")
    assert res["error"] == "ssrf_blocked"
    assert res["ip"] == "10.0.0.5"


def test_hostname_pins_first_address(monkeypatch):
    monkeypatch.setattr(resolver, "lookup_addresses", lambda h: ["8.8.8.8", "1.1.1.1"])
    res = resolver.resolve_target("ok.test")
    assert res["error"] is None and res["ip"] == "8.8.8.8"
    assert res["addresses"] == ["8.8.8.8", "1.1.1.1"]


def test_network_ssrf_check():
    assert resolver.network_ssrf_blocked(ipaddress.ip_network("10.0.0.0/24"))
    assert resolver.network_ssrf_blocked(ipaddress.ip_network("192.0.0.0/22"))
    assert not resolver.network_ssrf_blocked(ipaddress.ip_network("8.8.8.0/24"))


def test_scan_of_internal_target_is_refused(app_client):
    with app_client.stream("GET", "/api/scan", params={"target": "127.0.0.1"}) as resp:
        first = next(resp.iter_lines())
    event = json.loads(first.removeprefix("data: "))
    assert event["status"] == 403


# ── Pinning is honoured by the API ────────────────────────────────────────────

def test_audit_uses_pinned_ip(app_client, monkeypatch, allow_private):
    calls = []

    async def fake_audit(target, ports, pinned_ip=None):
        calls.append((target, pinned_ip))
        return {"headers": {}, "technologies": {}, "paths": {}}

    monkeypatch.setattr(main, "run_full_audit", fake_audit)
    resp = app_client.get("/api/audit", params={"target": "127.0.0.1", "open_ports": "80"})
    assert resp.status_code == 200
    assert calls == [("127.0.0.1", "127.0.0.1")]


def test_ssl_uses_pinned_ip(app_client, monkeypatch, allow_private):
    calls = []

    def fake_ssl(hostname, ports, timeout, connect_host):
        calls.append((hostname, connect_host))
        return {"results": {}}

    monkeypatch.setattr(main, "analyze_ssl_for_ports", fake_ssl)
    resp = app_client.get("/api/ssl", params={"target": "127.0.0.1", "open_ports": "443"})
    assert resp.status_code == 200
    assert calls == [("127.0.0.1", "127.0.0.1")]


# ── Auditor path probes go through safe_http ──────────────────────────────────

async def test_sensitive_paths_do_not_follow_redirects(monkeypatch):
    monkeypatch.setattr(resolver, "is_ssrf_blocked", lambda ip: ip == "127.0.0.2")
    port = [0]
    routes = {
        "/.env":   lambda r: (200, {}, b"SECRET=1"),
        "/admin/": lambda r: (302, {"Location": f"http://127.0.0.2:{port[0]}/"}, b""),
    }
    async with LoopbackHTTPServer(routes) as srv:
        port[0] = srv.port
        async with auditor._AuditSession({"site.test": "127.0.0.1"}) as session:
            res = await auditor._scan_sensitive_paths(f"http://site.test:{srv.port}", session)
        hosts = {r.headers["host"] for r in srv.requests}

    found = {f["path"]: f for f in res["found"]}
    assert found["/.env"]["accessible"] is True
    assert found["/admin/"]["status_code"] == 302 and not found["/admin/"]["accessible"]
    assert hosts == {f"site.test:{srv.port}"}


# ── Screenshot proxy (Chromium never touches the network itself) ─────────────

class FakeRoute:
    def __init__(self):
        self.fulfilled = None
        self.aborted = None

    async def fulfill(self, **kw):
        self.fulfilled = kw

    async def abort(self, reason="failed"):
        self.aborted = reason


class FakeRequest:
    def __init__(self, url, method="GET"):
        self.url = url
        self.method = method
        self.headers = {"accept": "*/*", "accept-encoding": "br", "host": "evil"}
        self.post_data_buffer = None


@pytest.fixture
async def page_server(monkeypatch):
    monkeypatch.setattr(resolver, "is_ssrf_blocked", lambda ip: ip == "127.0.0.2")
    routes = {"/": lambda r: (200, {"Content-Type": "text/html", "Content-Encoding": "identity"},
                              b"<h1>hi</h1>")}
    async with LoopbackHTTPServer(routes) as srv:
        yield srv


async def test_route_proxy_fulfils_pinned_target(page_server):
    import safe_http
    async with safe_http.make_client() as client:
        proxy = scan_service._RouteProxy(client, {"web.test": "127.0.0.1"})
        route = FakeRoute()
        await proxy(route, FakeRequest(page_server.url("/", host="web.test")))
    assert route.fulfilled["status"] == 200
    assert route.fulfilled["body"] == b"<h1>hi</h1>"
    assert "content-encoding" not in {k.lower() for k in route.fulfilled["headers"]}
    assert page_server.requests[0].headers["host"] == f"web.test:{page_server.port}"


async def test_route_proxy_blocks_internal_subresource(page_server):
    import safe_http
    async with safe_http.make_client() as client:
        proxy = scan_service._RouteProxy(client, {"web.test": "127.0.0.1"})
        route = FakeRoute()
        await proxy(route, FakeRequest(f"http://127.0.0.2:{page_server.port}/"))
    assert route.aborted == "blockedbyclient"
    assert proxy.blocked == 1
    assert page_server.requests == []


async def test_route_proxy_blocks_other_schemes(page_server):
    import safe_http
    async with safe_http.make_client() as client:
        proxy = scan_service._RouteProxy(client, {})
        route = FakeRoute()
        await proxy(route, FakeRequest("file:///etc/passwd"))
    assert route.aborted == "blockedbyclient"


async def test_route_proxy_caps_request_count(page_server, monkeypatch):
    import safe_http
    monkeypatch.setattr(scan_service, "SCREENSHOT_MAX_REQUESTS", 2)
    async with safe_http.make_client() as client:
        proxy = scan_service._RouteProxy(client, {"web.test": "127.0.0.1"})
        routes = [FakeRoute() for _ in range(3)]
        for r in routes:
            await proxy(r, FakeRequest(page_server.url("/", host="web.test")))
    assert routes[2].aborted == "blockedbyclient"


def test_browser_cannot_reach_network_directly():
    args = scan_service.BROWSER_ARGS
    assert "--proxy-server=http://127.0.0.1:9" in args
    assert "--proxy-bypass-list=<-loopback>" in args
    assert "--host-resolver-rules=MAP * ~NOTFOUND" in args


def test_screenshot_capture_passes_pinned_ip(app_client, monkeypatch, allow_private):
    calls = []

    async def fake_take(hostname, ip, port):
        calls.append((hostname, ip, port))
        limits.screenshots.release()

    monkeypatch.setattr(main, "take_screenshot", fake_take)
    resp = app_client.post("/api/screenshot/capture", params={"target": "127.0.0.1", "port": 8080})
    assert resp.status_code == 200
    assert calls == [("127.0.0.1", "127.0.0.1", 8080)]
    assert limits.screenshots.in_use == 0


def test_screenshot_url():
    assert scan_service.screenshot_url("a.test", 80) == "http://a.test"
    assert scan_service.screenshot_url("a.test", 8443) == "https://a.test:8443"
    assert scan_service.screenshot_url("2001:db8::1", 443) == "https://[2001:db8::1]"
