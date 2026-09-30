"""Point 5 (+8): authentication, Host checks, admin gating, headers, limits."""

import pytest

import security
from conftest import TEST_TOKEN


# ── Authentication ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/api/config", "/api/scan?target=127.0.0.1", "/api/discover?cidr=127.0.0.0/30",
    "/api/cve/cache-stats", "/api/screenshot?target=x",
])
def test_api_requires_token(anon_client, path):
    resp = anon_client.get(path)
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthorized"


def test_wrong_bearer_is_rejected(anon_client):
    resp = anon_client.get("/api/config", headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401


def test_bearer_token_is_accepted(app_client):
    assert app_client.get("/api/config").status_code == 200


def test_ui_is_public(anon_client):
    assert anon_client.get("/").status_code == 200
    assert anon_client.get("/static/main.js").status_code == 200


def test_cookie_login_flow(anon_client):
    assert anon_client.get("/api/auth/status").json() == {"authenticated": False}
    assert anon_client.post("/api/auth", json={"token": "bad"}).status_code == 401

    resp = anon_client.post("/api/auth", json={"token": TEST_TOKEN})
    assert resp.status_code == 204
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert TEST_TOKEN.lower() not in cookie          # the raw token is never stored

    assert anon_client.get("/api/auth/status").json() == {"authenticated": True}
    assert anon_client.get("/api/config").status_code == 200

    assert anon_client.post("/api/auth/logout").status_code == 204
    assert anon_client.get("/api/config").status_code == 401


def test_login_attempts_are_rate_limited(anon_client):
    codes = [anon_client.post("/api/auth", json={"token": "bad"}).status_code for _ in range(12)]
    assert codes[:10] == [401] * 10
    assert codes[10:] == [429, 429]


# ── Host / Origin ─────────────────────────────────────────────────────────────

def test_unknown_host_header_is_rejected(app_client):
    resp = app_client.get("/", headers={"Host": "attacker.test"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_host"


def test_allowed_host_with_port(app_client):
    assert app_client.get("/api/config", headers={"Host": "127.0.0.1:8000"}).status_code == 200


def test_cross_origin_post_is_rejected(app_client):
    resp = app_client.post(
        "/api/export/md", json={}, headers={"Origin": "https://attacker.test"},
    )
    assert resp.status_code == 403


def test_no_cors_headers(app_client):
    resp = app_client.get("/api/config", headers={"Origin": "https://attacker.test"})
    assert "access-control-allow-origin" not in resp.headers


# ── Admin routes ──────────────────────────────────────────────────────────────

def test_admin_disabled_by_default(app_client):
    assert app_client.get("/api/admin/status").status_code == 404
    assert app_client.post("/api/admin/reload-signatures").status_code == 404


def test_admin_enabled_explicitly(app_client, monkeypatch):
    monkeypatch.setenv("LUKITA_ENABLE_ADMIN", "true")
    security.reset_settings()
    resp = app_client.get("/api/admin/status")
    assert resp.status_code == 200
    assert "limits" in resp.json()


def test_admin_still_requires_token(anon_client, monkeypatch):
    monkeypatch.setenv("LUKITA_ENABLE_ADMIN", "true")
    security.reset_settings()
    assert anon_client.get("/api/admin/status").status_code == 401


# ── Security headers ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", ["/", "/static/main.js", "/api/config", "/api/nope"])
def test_security_headers_everywhere(app_client, path):
    h = app_client.get(path).headers
    assert "script-src 'self'" in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"


def test_security_headers_on_rejections(anon_client):
    assert "content-security-policy" in anon_client.get("/api/config").headers


def test_index_has_no_inline_handlers(anon_client):
    html = anon_client.get("/").text
    for attr in ("onclick=", "onmouseover=", "onmouseout=", "<script>"):
        assert attr not in html


# ── Rate limit / body size ────────────────────────────────────────────────────

def test_rate_limit(app_client, monkeypatch):
    monkeypatch.setenv("LUKITA_RATE_LIMIT", "3")
    security.reset_settings()
    codes = [app_client.get("/api/config").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_declared_body_too_large(app_client, monkeypatch):
    monkeypatch.setenv("LUKITA_MAX_BODY_BYTES", "100")
    security.reset_settings()
    resp = app_client.post("/api/export/md", content=b"x" * 500,
                           headers={"Content-Type": "application/json"})
    assert resp.status_code == 413


def test_streamed_body_too_large(app_client, monkeypatch):
    monkeypatch.setenv("LUKITA_MAX_BODY_BYTES", "100")
    security.reset_settings()

    def chunks():
        for _ in range(10):
            yield b"x" * 50

    resp = app_client.post("/api/export/md", content=chunks(),
                           headers={"Content-Type": "application/json"})
    assert resp.status_code == 413


# ── Settings / exposure rules ─────────────────────────────────────────────────

def test_non_loopback_without_token_is_refused(monkeypatch):
    monkeypatch.delenv("LUKITA_API_TOKEN")
    monkeypatch.setenv("LUKITA_HOST", "0.0.0.0")
    with pytest.raises(security.ConfigurationError):
        security.load_settings()


def test_short_token_is_refused(monkeypatch):
    monkeypatch.setenv("LUKITA_API_TOKEN", "short")
    with pytest.raises(security.ConfigurationError):
        security.load_settings()


def test_loopback_without_token_generates_one(monkeypatch):
    monkeypatch.delenv("LUKITA_API_TOKEN")
    s = security.load_settings()
    assert not s.token_from_env and len(s.token) >= 32
    assert security.load_settings().token != s.token


def test_generated_token_not_served_off_loopback(anon_client, monkeypatch):
    # TestClient reports the server address as "testserver" (not loopback):
    # with only an auto-generated token the API must refuse to serve.
    monkeypatch.delenv("LUKITA_API_TOKEN")
    security.reset_settings()
    resp = anon_client.get("/")
    assert resp.status_code == 503
    assert resp.json()["error"] == "token_required"


def test_default_allowed_hosts(monkeypatch):
    monkeypatch.delenv("LUKITA_ALLOWED_HOSTS")
    assert security.load_settings().allowed_hosts == {"127.0.0.1", "localhost", "::1"}


def test_login_url_keeps_token_in_fragment(monkeypatch):
    monkeypatch.delenv("LUKITA_API_TOKEN")
    s = security.load_settings()
    assert security.login_url(s, 8000) == f"http://127.0.0.1:8000/#token={s.token}"


@pytest.mark.parametrize("header,expected", [
    ("localhost:8000", "localhost"), ("[::1]:8000", "::1"), ("[::1]", "::1"),
    ("::1", "::1"), ("Example.TEST", "example.test"),
])
def test_host_parsing(header, expected):
    assert security._host_without_port(header) == expected


def test_run_py_refuses_public_bind_without_token(monkeypatch, capsys):
    import run
    import uvicorn

    monkeypatch.delenv("LUKITA_API_TOKEN")
    monkeypatch.setenv("LUKITA_HOST", "0.0.0.0")
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("must not start"))
    assert run.main() == 2
    assert "LUKITA_API_TOKEN is required" in capsys.readouterr().err


def test_run_py_binds_loopback_by_default(monkeypatch):
    import run
    import uvicorn

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: calls.append(k))
    assert run.main() == 0
    assert calls[0]["host"] == "127.0.0.1" and calls[0]["workers"] == 1


def test_invalid_setting_refuses_start(monkeypatch, capsys):
    import run
    import uvicorn

    monkeypatch.setenv("LUKITA_RATE_LIMIT", "lots")
    security.reset_settings()
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("must not start"))
    assert run.main() == 2
    assert "LUKITA_RATE_LIMIT" in capsys.readouterr().err
