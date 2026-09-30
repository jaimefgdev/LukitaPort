"""Point 17: base URL keeps the port; signatures are pre-compiled."""

import json

import pytest

import auditor
from http_helpers import LoopbackHTTPServer


@pytest.mark.parametrize("ports,expected", [
    ([8080], ["http://site.test:8080"]),
    ([8443, 80], ["https://site.test:8443", "http://site.test"]),
    ([443, 8888], ["https://site.test", "http://site.test:8888"]),
    ([22], ["https://site.test", "http://site.test"]),
])
def test_candidate_base_urls(ports, expected):
    assert auditor._candidate_base_urls("site.test", ports) == expected


def test_ipv6_base_url():
    assert auditor._candidate_base_urls("2001:db8::1", [8080]) == ["http://[2001:db8::1]:8080"]


async def test_full_audit_on_non_default_port(monkeypatch, allow_private):
    page = b'<html><meta name="generator" content="WordPress 6.5"><link href="/wp-content/x.css"></html>'
    routes = {
        "/": lambda r: (200, {"Content-Type": "text/html", "Server": "nginx/1.25",
                              "X-Frame-Options": "DENY",
                              "Strict-Transport-Security": "max-age=1"}, page),
        "/robots.txt": lambda r: (200, {}, b"User-agent: *"),
    }
    async with LoopbackHTTPServer(routes) as srv:
        monkeypatch.setattr(auditor, "_WEB_PORTS", (("http", srv.port),))
        res = await auditor.run_full_audit("site.test", [srv.port], pinned_ip="127.0.0.1")
        hosts = {r.headers["host"] for r in srv.requests}

    assert res["headers"]["url"] == f"http://site.test:{srv.port}"
    present = {h["header"] for h in res["headers"]["present"]}
    assert {"X-Frame-Options", "Strict-Transport-Security"} <= present
    assert res["headers"]["dangerous"][0]["header"] == "Server"
    names = {t["name"] for t in res["technologies"]["technologies"]}
    assert "Wordpress" in names or "WordPress" in names
    assert any(f["path"] == "/robots.txt" for f in res["paths"]["found"])
    assert hosts == {f"site.test:{srv.port}"}         # never re-resolved


def test_invalid_signature_regex_is_skipped(tmp_path, monkeypatch):
    sig_file = tmp_path / "sigs.json"
    sig_file.write_text(json.dumps([
        {"name": "Good", "body": ["good-marker"], "headers": {"X-Test": "ok\\d+"}},
        {"name": "Bad", "body": ["(unclosed"], "headers": {"X-Bad": "[z-a]"}},
    ]))
    monkeypatch.setattr(auditor, "_SIG_FILE", sig_file)
    sigs = auditor._load_signatures()
    good, bad = sigs
    assert good["_body"][0].search("GOOD-MARKER")          # case-insensitive
    assert good["_headers"]["x-test"].search("ok42")
    assert bad["_body"] == [] and bad["_headers"] == {}


def test_shipped_signatures_all_compile():
    for sig in auditor._load_signatures():
        assert len(sig["_body"]) == len(sig.get("body", []))
        assert len(sig["_headers"]) == len(sig.get("headers", {}))
