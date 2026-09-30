"""
scanner.py
──────────
Async TCP connect scanner.

Concurrency model
─────────────────
A fixed pool of worker tasks pulls ports from a queue and pushes results to
another queue that ``scan_ports_stream`` yields from.  There is never one
task per port, so a full 65 535-port scan costs ``max_concurrent`` tasks,
not 65 535.  When the consumer stops iterating (client disconnect, error,
``aclose()``) the ``finally`` block cancels and awaits every worker, so no
probe keeps running in the background.

Result states
─────────────
open      TCP handshake completed.
closed    Connection refused (RST).
filtered  Timeout, or host/network unreachable (ICMP) — like nmap.

Local resource exhaustion (EMFILE/ENFILE/ENOBUFS) says nothing about the
target, so it is never reported as a port state: the probe is retried with
back-off and, if it keeps failing, the scan is aborted with
``ScanResourceError``.  The effective concurrency is also capped by the
process file-descriptor limit so this should not normally happen.
"""

from __future__ import annotations

import asyncio
import errno
import random
import socket
from typing import Optional
from collections.abc import AsyncGenerator

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 9200, 27017,
]

SERVICE_MAP = {
    21: "FTP",    22: "SSH",        23: "Telnet",      25: "SMTP",
    53: "DNS",    80: "HTTP",       110: "POP3",        111: "RPC",
    135: "MSRPC", 139: "NetBIOS",   143: "IMAP",        443: "HTTPS",
    445: "SMB",   465: "SMTPS",     587: "SMTP/TLS",    993: "IMAPS",
    995: "POP3S", 1433: "MSSQL",    1521: "Oracle DB",  1723: "PPTP",
    3306: "MySQL", 3389: "RDP",     5432: "PostgreSQL",  5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",  8888: "HTTP-Dev",
    9200: "Elasticsearch", 27017: "MongoDB",
}

# ``jitter``: (min, max) seconds of random delay before each probe.
# ``shuffle``: probe ports in random order.
PROFILES: dict[str, dict] = {
    "stealth":    {"max_concurrent": 10,   "inter_delay": 0.5, "jitter": None,       "shuffle": False},
    "normal":     {"max_concurrent": 100,  "inter_delay": 0.0, "jitter": None,       "shuffle": False},
    "aggressive": {"max_concurrent": 1000, "inter_delay": 0.0, "jitter": None,       "shuffle": False},
    # Slow / low-profile mode.  NOT anonymous: the scanner's IP is still
    # visible to the target.  It only lowers the rate, randomises the timing
    # between probes and the port order, which makes simple threshold-based
    # detection less likely.
    "slow":       {"max_concurrent": 3,    "inter_delay": 0.0, "jitter": (0.5, 3.0), "shuffle": True},
}

# errno values meaning "the target (or the path to it) did not answer".
_UNREACHABLE_ERRNOS = frozenset(
    e for e in (
        getattr(errno, "EHOSTUNREACH", None),
        getattr(errno, "ENETUNREACH", None),
        getattr(errno, "EHOSTDOWN", None),
        getattr(errno, "ENETDOWN", None),
        getattr(errno, "ETIMEDOUT", None),
        getattr(errno, "EACCES", None),        # blocked by a local firewall rule
        getattr(errno, "EPERM", None),
    ) if e is not None
)
_REFUSED_ERRNOS = frozenset(
    e for e in (
        getattr(errno, "ECONNREFUSED", None),
        getattr(errno, "ECONNRESET", None),
    ) if e is not None
)
# errno values meaning *we* ran out of resources.
_RESOURCE_ERRNOS = frozenset(
    e for e in (
        getattr(errno, "EMFILE", None),
        getattr(errno, "ENFILE", None),
        getattr(errno, "ENOBUFS", None),
        getattr(errno, "EADDRNOTAVAIL", None),  # ephemeral ports exhausted
    ) if e is not None
)

_RESOURCE_RETRIES = 5
_FD_RESERVE       = 128      # descriptors kept free for the rest of the app


class ScanResourceError(RuntimeError):
    """The local machine ran out of sockets/descriptors; the scan stopped."""


def get_service(port: int) -> str:
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"


def fd_budget() -> int:
    """Max concurrent sockets allowed by the soft RLIMIT_NOFILE (≥ 1)."""
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ImportError, ValueError, OSError):   # Windows / exotic platforms
        return 500
    if soft == resource.RLIM_INFINITY:
        return 10_000
    return max(1, soft - _FD_RESERVE)


def effective_concurrency(requested: int) -> int:
    return max(1, min(requested, fd_budget()))


_BANNER_STRATEGY: dict[int, tuple[str, Optional[bytes]]] = {
    80:    ("probe", b"HEAD / HTTP/1.0\r\nHost: ?\r\n\r\n"),
    8080:  ("probe", b"HEAD / HTTP/1.0\r\nHost: ?\r\n\r\n"),
    8888:  ("probe", b"HEAD / HTTP/1.0\r\nHost: ?\r\n\r\n"),
    9200:  ("probe", b"GET / HTTP/1.0\r\nHost: ?\r\n\r\n"),
    6379:  ("probe", b"PING\r\n"),
    443:   ("skip",  None), 8443:  ("skip", None),
    3389:  ("skip",  None), 445:   ("skip", None),
    139:   ("skip",  None), 1433:  ("skip", None),
    1521:  ("skip",  None), 3306:  ("skip", None),
    5432:  ("skip",  None), 27017: ("skip", None),
    465:   ("skip",  None), 993:   ("skip", None), 995: ("skip", None),
    21:    ("read",  None), 22: ("read", None), 23: ("read", None),
    25:    ("read",  None), 110: ("read", None), 143: ("read", None),
    587:   ("read",  None), 5900: ("read", None),
}

_DEFAULT_STRATEGY = ("read", None)
_BANNER_TIMEOUT   = 0.8


async def _grab_banner(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int,
) -> Optional[str]:
    strategy, probe = _BANNER_STRATEGY.get(port, _DEFAULT_STRATEGY)

    if strategy == "skip":
        return None

    try:
        if strategy == "probe" and probe:
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=0.3)

        raw = await asyncio.wait_for(reader.read(512), timeout=_BANNER_TIMEOUT)
        if not raw:
            return None

        if strategy == "probe" and probe and (probe.startswith(b"HEAD") or probe.startswith(b"GET")):
            first_line = raw.split(b"\r\n")[0].decode("utf-8", errors="replace").strip()
            return first_line[:120] if first_line else None

        banner = " ".join(raw.decode("utf-8", errors="replace").strip().split())
        return banner[:120] if banner else None

    except (TimeoutError, OSError):
        return None


async def _scan_port_async(ip: str, port: int, timeout: float) -> dict:
    """
    Probe one port.  Raises ``OSError`` only for local resource errors
    (see ``_RESOURCE_ERRNOS``); every target-related outcome is a state.
    """
    result = {
        "port": port, "state": "closed", "service": get_service(port),
        "response_time_ms": None, "version": None, "banner": None,
    }

    loop  = asyncio.get_running_loop()
    start = loop.time()

    def elapsed_ms() -> float:
        return round((loop.time() - start) * 1000, 2)

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except TimeoutError:
        result["state"] = "filtered"
        result["response_time_ms"] = elapsed_ms()
        return result
    except OSError as exc:
        if exc.errno in _RESOURCE_ERRNOS:
            raise
        result["response_time_ms"] = elapsed_ms()
        if isinstance(exc, ConnectionRefusedError) or exc.errno in _REFUSED_ERRNOS:
            result["state"] = "closed"
        else:
            # Unreachable, or an unexpected error: we got no answer from the
            # port, which is what "filtered" means.
            result["state"] = "filtered"
            if exc.errno not in _UNREACHABLE_ERRNOS:
                result["error"] = errno.errorcode.get(exc.errno or 0, str(exc))
        return result

    result["state"] = "open"
    result["response_time_ms"] = elapsed_ms()
    try:
        banner = await _grab_banner(reader, writer, port)
        if banner:
            result["banner"] = banner
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            pass
    return result


async def _probe_with_retry(ip: str, port: int, timeout: float) -> dict:
    delay = 0.05
    for attempt in range(_RESOURCE_RETRIES + 1):
        try:
            return await _scan_port_async(ip, port, timeout)
        except OSError as exc:
            if exc.errno not in _RESOURCE_ERRNOS:
                raise
            if attempt == _RESOURCE_RETRIES:
                raise ScanResourceError(
                    f"Local resources exhausted ({errno.errorcode.get(exc.errno or 0, str(exc.errno))}); "
                    "lower the concurrency (profile) or raise the open-files limit."
                ) from exc
            await asyncio.sleep(delay)
            delay *= 2
    raise AssertionError("unreachable")  # pragma: no cover


async def scan_ports_stream(
    ip: str,
    ports: list,
    timeout: float = 1.0,
    max_concurrent: int = 100,
    inter_delay: float = 0.0,
    jitter: Optional[tuple[float, float]] = None,
    shuffle: bool = False,
    rng: Optional[random.Random] = None,
) -> AsyncGenerator[dict, None]:
    """
    Yield one result dict per port, in completion order, with progress
    fields.  Raises ``ScanResourceError`` if local resources run out.
    """
    total = len(ports)
    if total == 0:
        return
    rng = rng or random.SystemRandom()
    order = list(ports)
    if shuffle:
        rng.shuffle(order)

    port_queue: asyncio.Queue[int] = asyncio.Queue()
    for p in order:
        port_queue.put_nowait(p)
    results: asyncio.Queue[dict | BaseException] = asyncio.Queue()

    async def worker() -> None:
        while True:
            try:
                port = port_queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if jitter:
                await asyncio.sleep(rng.uniform(*jitter))
            try:
                res = await _probe_with_retry(ip, port, timeout)
            except Exception as exc:
                # A dead worker must never leave the consumer waiting forever.
                await results.put(exc)
                return
            await results.put(res)
            if inter_delay > 0:
                await asyncio.sleep(inter_delay)

    workers = [
        asyncio.create_task(worker())
        for _ in range(min(effective_concurrency(max_concurrent), total))
    ]
    try:
        for completed in range(1, total + 1):
            item = await results.get()
            if isinstance(item, BaseException):
                raise item
            item["progress"] = round((completed / total) * 100, 1)
            item["scanned"]  = completed
            item["total"]    = total
            yield item
    finally:
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)


def get_port_range(
    mode: str, port_start: Optional[int] = None, port_end: Optional[int] = None,
) -> list[int]:
    if mode == "quick":
        return COMMON_PORTS
    if mode == "full":
        return list(range(1, 65536))
    if mode == "custom" and port_start is not None and port_end is not None:
        return list(range(port_start, port_end + 1))
    return COMMON_PORTS
