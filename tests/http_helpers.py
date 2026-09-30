"""
Minimal asyncio HTTP/1.1 server on 127.0.0.1 for tests.

Routes are ``path -> handler(request) -> (status, headers, body)``.  Every
received request is recorded in ``server.requests``.  No external network is
involved: the server binds to an ephemeral loopback port.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from collections.abc import Callable


@dataclass
class Request:
    method:  str
    path:    str
    headers: dict[str, str]
    body:    bytes


Handler = Callable[[Request], tuple[int, dict[str, str], bytes]]


@dataclass
class LoopbackHTTPServer:
    routes:   dict[str, Handler]
    requests: list[Request] = field(default_factory=list)
    port:     int = 0
    _server:  asyncio.AbstractServer | None = None

    async def __aenter__(self) -> LoopbackHTTPServer:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc) -> None:
        self._server.close()
        await self._server.wait_closed()

    def url(self, path: str = "/", host: str = "127.0.0.1") -> str:
        return f"http://{host}:{self.port}{path}"

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            body = b""
            if headers.get("content-length"):
                body = await reader.readexactly(int(headers["content-length"]))
            req = Request(method, path, headers, body)
            self.requests.append(req)

            handler = self.routes.get(path.split("?", 1)[0])
            status, resp_headers, resp_body = (
                handler(req) if handler else (404, {}, b"not found")
            )
            out = [f"HTTP/1.1 {status} X"]
            resp_headers = {"Content-Length": str(len(resp_body)), "Connection": "close", **resp_headers}
            out += [f"{k}: {v}" for k, v in resp_headers.items()]
            writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + resp_body)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
