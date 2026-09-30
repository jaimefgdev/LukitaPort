"""
Browser (end-to-end) tests of the UI error handling and sign-in flow.

A real LukitaPort server runs in a thread on 127.0.0.1 and Chromium drives
the UI.  Nothing is ever scanned: the targets used here are rejected by the
server (SSRF policy, validation, authentication) before any probe.

Skipped when Playwright's Chromium is not installed (unless
LUKITA_E2E_REQUIRE=1, as in the CI "e2e" job).  LUKITA_E2E_CHROMIUM may
point at a specific Chromium binary.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time

import pytest

from conftest import TEST_TOKEN

sync_api = pytest.importorskip("playwright.sync_api")
pytestmark = pytest.mark.e2e


@pytest.fixture
def live_server(monkeypatch):
    import uvicorn

    # No shared screenshot browser inside the server for these tests.
    monkeypatch.setitem(sys.modules, "playwright.async_api", None)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(
        "main:app", host="127.0.0.1", port=port, log_level="warning", lifespan="on",
    ))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started:
        if time.time() > deadline or not thread.is_alive():
            pytest.fail("LukitaPort test server did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(10)


@pytest.fixture
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(executable_path=os.getenv("LUKITA_E2E_CHROMIUM") or None)
        except Exception as exc:
            if os.getenv("LUKITA_E2E_REQUIRE") == "1":     # the CI e2e job must not skip
                raise
            pytest.skip(f"Chromium not available: {exc}")
        yield b
        b.close()


def _open_app(browser, base, fragment_token=TEST_TOKEN):
    context = browser.new_context()
    page = context.new_page()
    url = f"{base}/#token={fragment_token}" if fragment_token else f"{base}/"
    page.goto(url)
    if page.is_visible("#btn-accept"):
        page.click("#btn-accept")
    return context, page


def _expect(locator):
    return sync_api.expect(locator)


# ── Fix 1: errors are always shown ────────────────────────────────────────────

def test_ssrf_blocked_scan_shows_message(browser, live_server):
    _, page = _open_app(browser, live_server)
    _expect(page.locator("#auth-overlay")).to_be_hidden()
    page.fill("#target", "127.0.0.1")
    page.click("#btn-scan")
    body = page.locator("#results-body")
    _expect(body).to_contain_text("Destino bloqueado")
    _expect(body).not_to_contain_text("Sin resultados")
    _expect(page.locator("#status-target")).to_have_text("Error")


def test_unauthorised_scan_shows_message_and_sign_in(browser, live_server):
    context, page = _open_app(browser, live_server)
    _expect(page.locator("#auth-overlay")).to_be_hidden()
    context.clear_cookies()                     # session lost (e.g. server restarted)
    page.fill("#target", "127.0.0.1")
    page.click("#btn-scan")
    _expect(page.locator("#results-body")).to_contain_text("Sesión no válida")
    _expect(page.locator("#auth-overlay")).to_be_visible()
    _expect(page.locator("#auth-error")).to_contain_text("sesión ya no es válida")


def test_invalid_scan_parameters_show_message(browser, live_server):
    _, page = _open_app(browser, live_server)
    page.fill("#target", "127.0.0.1")
    # Bypass the UI's own range check: an out-of-range timeout only the
    # server rejects.
    page.evaluate("() => { const t = document.getElementById('timeout'); t.max = '99'; t.value = '99'; }")
    page.click("#btn-scan")
    _expect(page.locator("#results-body")).to_contain_text("timeout")


def test_discover_errors_are_shown(browser, live_server):
    _, page = _open_app(browser, live_server)
    page.fill("#discover-cidr", "10.0.0.0/8")
    page.click("#btn-discover")
    _expect(page.locator("#discover-output")).to_contain_text("Datos no válidos")
    page.fill("#discover-cidr", "10.0.0.0/24")
    page.click("#btn-discover")
    _expect(page.locator("#discover-output")).to_contain_text("Destino bloqueado")


def test_unauthorised_api_call_reopens_sign_in(browser, live_server):
    context, page = _open_app(browser, live_server)
    context.clear_cookies()
    page.fill("#subdomain-input", "example.test")
    page.click("#btn-subdomains")
    _expect(page.locator("#subdomain-output")).to_contain_text("Sesión no válida")
    _expect(page.locator("#auth-overlay")).to_be_visible()


# ── Fix 2: the fragment token always replaces the current session ─────────────

def test_new_fragment_in_open_tab_logs_in_again(browser, live_server):
    _, page = _open_app(browser, live_server)
    _expect(page.locator("#auth-overlay")).to_be_hidden()

    with page.expect_request(lambda r: r.url.endswith("/api/auth") and r.method == "POST"):
        page.evaluate(f"() => {{ location.hash = '#token={TEST_TOKEN}'; }}")
    _expect(page.locator("#auth-overlay")).to_be_hidden()
    _expect(page.locator("#toast")).to_contain_text("token de la URL")
    assert "#token" not in page.url


def test_invalid_fragment_drops_previous_session(browser, live_server):
    _, page = _open_app(browser, live_server)
    _expect(page.locator("#auth-overlay")).to_be_hidden()

    page.evaluate("() => { location.hash = '#token=not-the-right-token-123'; }")
    _expect(page.locator("#auth-overlay")).to_be_visible()
    _expect(page.locator("#auth-error")).to_contain_text("token de la URL no es válido")
    status = page.evaluate("async () => (await (await fetch('/api/auth/status')).json()).authenticated")
    assert status is False                       # the old session was not kept

    # Signing in with the right token through the dialog works again.
    page.fill("#auth-token", TEST_TOKEN)
    page.click("#auth-form button")
    _expect(page.locator("#auth-overlay")).to_be_hidden()


def test_fragment_on_first_load_wins_over_invalid_cookie(browser, live_server):
    context = browser.new_context()
    context.add_cookies([{"name": "lukita_session", "value": "stale", "url": live_server}])
    page = context.new_page()
    page.goto(f"{live_server}/#token={TEST_TOKEN}")
    _expect(page.locator("#auth-overlay")).to_be_hidden()
    status = page.evaluate("async () => (await (await fetch('/api/auth/status')).json()).authenticated")
    assert status is True
