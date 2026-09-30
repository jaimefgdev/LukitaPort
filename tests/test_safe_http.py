"""Point 6: pinned connections, validated redirects, bounded bodies."""

import httpx
import pytest

import resolver
import safe_http
from http_helpers import LoopbackHTTPServer


@pytest.fixture
def block_127_0_0_2(monkeypatch):
    """SSRF policy for these tests: 127.0.0.1 allowed, 127.0.0.2 'internal'."""
    monkeypatch.setattr(resolver, "is_ssrf_blocked", lambda ip: ip == "127.0.0.2")


def routes(port_ref):
    return {
        "/":               lambda r: (200, {}, f"host={r.headers.get('host')}".encode()),
        "/redir-ok":       lambda r: (302, {"Location": "/"}, b""),
        "/redir-internal": lambda r: (302, {"Location": f"http://127.0.0.2:{port_ref[0]}/"}, b""),
        "/redir-file":     lambda r: (302, {"Location": "file:///etc/passwd"}, b""),
        "/redir-loop":     lambda r: (302, {"Location": "/redir-loop"}, b""),
        "/big":            lambda r: (200, {}, b"x" * 100_000),
    }


@pytest.fixture
async def server():
    port_ref = [0]
    async with LoopbackHTTPServer(routes(port_ref)) as srv:
        port_ref[0] = srv.port
        yield srv


async def test_pinned_host_connects_to_ip_and_keeps_host_header(server, block_127_0_0_2):
    # "target.test" is never resolved: the network guard would fail the test
    # on any DNS lookup, so this proves the connection used the pinned IP.
    async with safe_http.make_client() as client:
        resp = await safe_http.fetch(
            client, server.url("/", host="target.test"), pinned={"target.test": "127.0.0.1"},
        )
    assert resp.status == 200
    assert resp.text == f"host=target.test:{server.port}"
    assert resp.url == server.url("/", host="target.test")


async def test_same_host_redirect_is_followed(server, block_127_0_0_2):
    async with safe_http.make_client() as client:
        resp = await safe_http.fetch(client, server.url("/redir-ok"))
    assert resp.status == 200
    assert [r.path for r in server.requests] == ["/redir-ok", "/"]


async def test_redirect_to_internal_address_is_blocked(server, block_127_0_0_2):
    async with safe_http.make_client() as client:
        with pytest.raises(safe_http.BlockedDestination):
            await safe_http.fetch(client, server.url("/redir-internal"))
    assert [r.path for r in server.requests] == ["/redir-internal"]


async def test_redirect_to_other_scheme_is_blocked(server, block_127_0_0_2):
    async with safe_http.make_client() as client:
        with pytest.raises(safe_http.BlockedDestination):
            await safe_http.fetch(client, server.url("/redir-file"))


async def test_redirect_not_followed_when_disabled(server, block_127_0_0_2):
    async with safe_http.make_client() as client:
        resp = await safe_http.fetch(client, server.url("/redir-internal"), max_redirects=0)
    assert resp.status == 302


async def test_redirect_loop_stops(server, block_127_0_0_2):
    async with safe_http.make_client() as client:
        resp = await safe_http.fetch(client, server.url("/redir-loop"), max_redirects=3)
    assert resp.status == 302
    assert len(server.requests) == 4


async def test_body_is_truncated(server, block_127_0_0_2):
    async with safe_http.make_client() as client:
        resp = await safe_http.fetch(client, server.url("/big"), max_bytes=1000)
    assert len(resp.body) == 1000 and resp.truncated


async def test_unpinned_host_resolving_internal_is_blocked(monkeypatch, block_127_0_0_2):
    monkeypatch.setattr(resolver, "lookup_addresses", lambda host: ["127.0.0.1", "127.0.0.2"])
    async with safe_http.make_client() as client:
        with pytest.raises(safe_http.BlockedDestination):
            await safe_http.fetch(client, "http://rebind.test/")


async def test_direct_internal_ip_is_blocked(block_127_0_0_2):
    async with safe_http.make_client() as client:
        with pytest.raises(safe_http.BlockedDestination):
            await safe_http.fetch(client, "http://127.0.0.2:1/")


def test_ipv6_pinning_builds_bracketed_url():
    url = httpx.URL("https://v6.test:8443/a").copy_with(host="::1")
    assert str(url) == "https://[::1]:8443/a"


async def test_https_sends_hostname_as_sni(tmp_path, block_127_0_0_2):
    import asyncio
    import ssl

    from tls_helpers import make_cert, write_pem

    cert, key = make_cert("sni.test", sans=("sni.test",))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*write_pem(tmp_path, "leaf", cert, key))
    seen: list[str] = []
    ctx.sni_callback = lambda sock, name, c: seen.append(name)

    async def handle(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    async with server:
        async with safe_http.make_client() as client:
            resp = await safe_http.fetch(
                client, f"https://sni.test:{port}/", pinned={"sni.test": "127.0.0.1"},
            )
    assert resp.status == 200 and resp.text == "ok"
    assert seen == ["sni.test"]
