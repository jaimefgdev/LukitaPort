"""Point 19: NVD client — lock scope, Retry-After, cache, API key, CPE."""

import asyncio
from datetime import datetime, timedelta, UTC
from email.utils import format_datetime

import httpx
import pytest

import cve_lookup


NVD_OK = {
    "totalResults": 1,
    "vulnerabilities": [{"cve": {
        "id": "CVE-2099-0001",
        "descriptions": [{"lang": "en", "value": "Test vuln"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "published": "2099-01-01T00:00:00",
        "references": [{"url": "https://example.invalid/advisory"}],
    }}],
}


@pytest.fixture(autouse=True)
def fast_nvd(monkeypatch):
    """No real spacing/back-off delays, fresh cache and timing state."""
    monkeypatch.setattr(cve_lookup, "NVD_REQUEST_DELAY", 0.0)
    monkeypatch.setattr(cve_lookup, "NVD_REQUEST_DELAY_KEY", 0.0)
    monkeypatch.setattr(cve_lookup, "_jittered_wait", lambda attempt: 0.01)
    monkeypatch.setattr(cve_lookup, "_last_request_time", 0.0)
    cve_lookup._cache.clear()


@pytest.fixture
def nvd(monkeypatch):
    """Install a MockTransport; returns the list of received requests."""
    state = {"handler": lambda req: httpx.Response(200, json=NVD_OK), "requests": []}

    def handler(request):
        state["requests"].append(request)
        return state["handler"](request)

    monkeypatch.setattr(cve_lookup, "_make_client",
                        lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    return state


async def test_keyword_lookup_and_cache(nvd):
    r1 = await cve_lookup.lookup_cves("OpenSSH", "8.9p1")
    r2 = await cve_lookup.lookup_cves("openssh", "8.9P1")
    assert r1["cves"][0]["id"] == "CVE-2099-0001" and r1["cves"][0]["severity"] == "CRITICAL"
    assert r2["cached"] is True
    assert len(nvd["requests"]) == 1
    assert nvd["requests"][0].url.params["keywordSearch"] == "OpenSSH 8.9p1"


async def test_cpe_lookup_uses_virtual_match_string(nvd):
    r = await cve_lookup.lookup_cves("nginx", "1.24.0", cpe="cpe:/a:igor_sysoev:nginx:1.24.0")
    params = nvd["requests"][0].url.params
    assert params["virtualMatchString"] == "cpe:2.3:a:igor_sysoev:nginx:1.24.0"
    assert "keywordSearch" not in params
    assert r["keyword_used"] == "cpe:2.3:a:igor_sysoev:nginx:1.24.0"


@pytest.mark.parametrize("cpe,expected", [
    ("cpe:/a:openbsd:openssh:8.9p1", "cpe:2.3:a:openbsd:openssh:8.9p1"),
    ("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*", "cpe:2.3:a:apache:http_server:2.4.58"),
    ("cpe:/a:openbsd:openssh", None),                 # no version
    ("cpe:/a:vendor:product:*", None),
    ("cpe:/o:linux:linux_kernel", None),
    ("garbage", None),
    ("", None),
])
def test_cpe_to_23(cpe, expected):
    assert cve_lookup.cpe_to_23(cpe) == expected


async def test_api_key_header(nvd, setenv):
    setenv(NVD_API_KEY="k-123")
    await cve_lookup.lookup_cves("x", "1")
    assert nvd["requests"][0].headers["apiKey"] == "k-123"
    assert cve_lookup._request_delay() == cve_lookup.NVD_REQUEST_DELAY_KEY


async def test_no_api_key_header_by_default(nvd):
    await cve_lookup.lookup_cves("x", "1")
    assert "apiKey" not in nvd["requests"][0].headers


async def test_429_then_success(nvd):
    responses = iter([httpx.Response(429, headers={"Retry-After": "0"}),
                      httpx.Response(200, json=NVD_OK)])
    nvd["handler"] = lambda req: next(responses)
    r = await cve_lookup.lookup_cves("x", "1")
    assert r["error"] is None and len(nvd["requests"]) == 2


async def test_persistent_429_reports_rate_limit(nvd):
    nvd["handler"] = lambda req: httpx.Response(429)
    r = await cve_lookup.lookup_cves("x", "1")
    assert "rate limit" in r["error"]
    assert len(nvd["requests"]) == cve_lookup._MAX_RETRIES


async def test_transport_error_then_success(nvd):
    calls = {"n": 0}

    def flaky(req):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("boom")
        return httpx.Response(200, json=NVD_OK)

    nvd["handler"] = flaky
    assert (await cve_lookup.lookup_cves("x", "1"))["error"] is None


async def test_backoff_does_not_hold_the_lock(nvd, monkeypatch):
    """While one lookup backs off after a 429, another must get through."""
    monkeypatch.setattr(cve_lookup, "_jittered_wait", lambda attempt: 0.3)
    order = []

    def handler(req):
        kw = req.url.params["keywordSearch"]
        order.append(kw)
        if kw == "slow 1" and order.count("slow 1") == 1:
            return httpx.Response(429)
        return httpx.Response(200, json=NVD_OK)

    nvd["handler"] = handler
    slow = asyncio.create_task(cve_lookup.lookup_cves("slow", "1"))
    await asyncio.sleep(0.05)                      # slow got its 429, now backing off
    fast = asyncio.create_task(cve_lookup.lookup_cves("fast", "1"))
    await asyncio.wait_for(fast, 0.2)              # completes during slow's back-off
    await slow
    assert order == ["slow 1", "fast 1", "slow 1"]


def test_retry_after_parsing():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert cve_lookup.parse_retry_after("12", now) == 12.0
    assert cve_lookup.parse_retry_after(format_datetime(now + timedelta(seconds=30)), now) == 30.0
    assert cve_lookup.parse_retry_after(format_datetime(now - timedelta(seconds=30)), now) == 0.0
    assert cve_lookup.parse_retry_after("soon", now) is None
    assert cve_lookup.parse_retry_after(None, now) is None


async def test_http_date_retry_after_is_used(nvd, monkeypatch):
    sleeps = []
    real_sleep = asyncio.sleep

    async def spy(d):
        sleeps.append(d)
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", spy)
    future = format_datetime(datetime.now(UTC) + timedelta(seconds=20), usegmt=True)
    responses = iter([httpx.Response(429, headers={"Retry-After": future}),
                      httpx.Response(200, json=NVD_OK)])
    nvd["handler"] = lambda req: next(responses)
    await cve_lookup.lookup_cves("x", "1")
    assert any(15 <= d <= 21 for d in sleeps)


def test_cache_is_bounded():
    assert cve_lookup._cache.maxsize == 500


async def test_batch_skips_unfingerprinted_and_bad_keys(nvd):
    res = await cve_lookup.lookup_cves_for_ports({
        "22":  {"name": "SSH", "product": "OpenSSH", "version": "8.9p1"},
        "80":  {"name": "HTTP"},                                    # no product/version
        "443": {"name": "HTTPS", "cpe": "cpe:/a:igor_sysoev:nginx:1.24.0"},
        "abc": {"name": "x", "product": "p", "version": "1"},       # ignored
        "25":  "not-a-dict",                                        # ignored
    })
    assert set(res) == {22, 80, 443}
    assert res[80]["skipped"] is True and "fingerprinting" in res[80]["error"]
    queries = [dict(r.url.params) for r in nvd["requests"]]
    assert {"keywordSearch": "OpenSSH 8.9p1"}.items() <= queries[0].items()
    assert queries[1]["virtualMatchString"] == "cpe:2.3:a:igor_sysoev:nginx:1.24.0"
    assert len(queries) == 2
