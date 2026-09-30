"""Point 22: one error format, correct status codes, typed responses."""

import pytest

import main
import models
import scan_service


def _is_error(resp, status, code):
    body = resp.json()
    assert resp.status_code == status, body
    assert body["ok"] is False and body["error"] == code and body["detail"]
    return body


def test_validation_error_format(app_client):
    body = _is_error(app_client.get("/api/resolve", params={"target": "not a host"}), 422, "validation_error")
    assert body["detail"].startswith("target:")
    assert body["errors"][0]["loc"] == ["query", "target"]


def test_missing_parameter(app_client):
    _is_error(app_client.get("/api/audit"), 422, "validation_error")


def test_unknown_route(app_client):
    _is_error(app_client.get("/api/does-not-exist"), 404, "not_found")


def test_wrong_method(app_client):
    _is_error(app_client.delete("/api/config"), 405, "method_not_allowed")


def test_ssrf_error_format(app_client):
    body = _is_error(app_client.get("/api/resolve", params={"target": "127.0.0.1"}), 403, "ssrf_blocked")
    assert "ALLOW_PRIVATE_IPS" in body["detail"]


def test_unresolvable_target(app_client, monkeypatch):
    async def fail(target, reverse_dns=False):
        return {"input": target, "ip": None, "hostname": None, "resolved": False,
                "error": "Name or service not known", "addresses": []}

    monkeypatch.setattr(main, "resolve_target", fail)
    _is_error(app_client.get("/api/resolve", params={"target": "nx.test"}), 400, "unresolvable")


def test_upstream_error_is_502(app_client, monkeypatch):
    async def down(domain):
        return {"error": "crt.sh unreachable", "subdomains": []}

    monkeypatch.setattr(main, "enumerate_subdomains", down)
    _is_error(app_client.get("/api/subdomains", params={"domain": "example.test"}), 502, "upstream_error")


def test_unexpected_exception_hides_details(app_client, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("secret /internal/path")

    monkeypatch.setattr(main, "lookup_cves", boom)
    from fastapi.testclient import TestClient
    client = TestClient(main.app, raise_server_exceptions=False,
                        headers=dict(app_client.headers))
    resp = client.get("/api/cve", params={"service": "x"})
    body = _is_error(resp, 500, "internal_error")
    assert "secret" not in resp.text and body["detail"] == "Internal server error."


def test_invalid_token_format(anon_client):
    _is_error(anon_client.post("/api/auth", json={"token": "nope"}), 401, "invalid_token")


def test_health_is_public_and_minimal(anon_client):
    resp = anon_client.get("/api/health")
    assert resp.status_code == 200 and resp.json() == {"ok": True}


def test_config_exposes_ui_constants(app_client):
    cfg = app_client.get("/api/config").json()
    assert cfg["nmap"] == {"timeoutBase": scan_service.NMAP_TIMEOUT_BASE,
                           "timeoutPerPort": scan_service.NMAP_TIMEOUT_PER_PORT}
    assert cfg["limits"]["cveBatch"] == 20


def test_openapi_documents_error_model(app_client):
    spec = app_client.get("/openapi.json").json()
    assert "ErrorResponse" in spec["components"]["schemas"]
    audit = spec["paths"]["/api/audit"]["get"]["responses"]
    assert audit["200"]["content"]["application/json"]["schema"]["$ref"].endswith("/AuditResponse")
    assert "403" in audit and "422" in audit


# ── Real service output validates against the response models ────────────────

async def test_real_audit_output_matches_model(monkeypatch, allow_private):
    import auditor
    from http_helpers import LoopbackHTTPServer

    routes = {"/": lambda r: (200, {"Server": "x", "X-Frame-Options": "DENY"}, b"<html>wp-content/</html>"),
              "/.env": lambda r: (200, {}, b"A=1")}
    async with LoopbackHTTPServer(routes) as srv:
        monkeypatch.setattr(auditor, "_WEB_PORTS", (("http", srv.port),))
        result = await auditor.run_full_audit("site.test", [srv.port], pinned_ip="127.0.0.1")
    models.AuditResponse.model_validate({"target": "site.test", "ip": "127.0.0.1", **result})


async def test_unreachable_audit_output_matches_model(monkeypatch, allow_private):
    import socket

    import auditor
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    monkeypatch.setattr(auditor, "_WEB_PORTS", (("http", port),))
    result = await auditor.run_full_audit("site.test", [port], pinned_ip="127.0.0.1")
    models.AuditResponse.model_validate({"target": "site.test", "ip": "127.0.0.1", **result})


def test_real_ssl_output_matches_model(tmp_path):
    from ssl_analyzer import analyze_ssl_for_ports
    from tls_helpers import LoopbackTLSServer, make_cert, write_pem

    cert, key = make_cert("localhost")
    with LoopbackTLSServer(*write_pem(tmp_path, "leaf", cert, key)) as srv:
        res = analyze_ssl_for_ports("127.0.0.1", [443], timeout=2, connect_host="127.0.0.1")
        assert res["results"]["443"]["error"]      # nothing on 443 — still valid shape
        from ssl_analyzer import analyze_ssl
        one = analyze_ssl("127.0.0.1", srv.port, timeout=2)
    models.SSLResponse.model_validate({"target": "t", "ip": "127.0.0.1", **res})
    models.SSLResult.model_validate(one)
    models.SSLResponse.model_validate({"target": "t", "ip": "1", **analyze_ssl_for_ports("x", [22])})


@pytest.mark.parametrize("raw,expected", [
    ("80", [80]), ("80, 443,80", [80, 443]), ("1,65535", [1, 65535]),
])
def test_parse_ports(raw, expected):
    assert models.parse_ports(raw, 10) == expected


@pytest.mark.parametrize("raw", ["", "0", "65536", "a", "1,,2", "1;2"])
def test_parse_ports_rejects(raw):
    with pytest.raises(ValueError):
        models.parse_ports(raw, 10)


def test_screenshot_capture_without_playwright_is_503(app_client, monkeypatch, allow_private):
    monkeypatch.setattr(main, "screenshots_supported", lambda: False)
    resp = app_client.post("/api/screenshot/capture", params={"target": "127.0.0.1"})
    _is_error(resp, 503, "screenshots_unavailable")


def test_docs_ui_disabled_schema_available(anon_client):
    assert anon_client.get("/docs").status_code == 404
    assert anon_client.get("/openapi.json").status_code == 200
