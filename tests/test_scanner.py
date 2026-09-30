"""Points 13–14 (+20 slow mode): worker pool, cancellation, error states."""

import asyncio
import errno
import random
import socket

import pytest

import scanner


def _free_port() -> int:
    """A loopback port with nothing listening (bound then released)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _collect(gen):
    return [r async for r in gen]


# ── Real loopback probes ──────────────────────────────────────────────────────

async def test_open_closed_and_banner_on_loopback():
    async def greet(reader, writer):
        writer.write(b"SSH-2.0-TestServer\r\n")
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()

    server = await asyncio.start_server(greet, "127.0.0.1", 0)
    open_port = server.sockets[0].getsockname()[1]
    closed_port = _free_port()
    async with server:
        results = await _collect(scanner.scan_ports_stream(
            "127.0.0.1", [open_port, closed_port], timeout=1.0, max_concurrent=5,
        ))

    by_port = {r["port"]: r for r in results}
    assert by_port[open_port]["state"] == "open"
    assert by_port[open_port]["banner"] == "SSH-2.0-TestServer"
    assert by_port[closed_port]["state"] == "closed"
    assert [r["scanned"] for r in results] == [1, 2]
    assert results[-1]["progress"] == 100.0


async def test_empty_port_list():
    assert await _collect(scanner.scan_ports_stream("127.0.0.1", [])) == []


# ── Worker pool & cancellation (mocked probes) ────────────────────────────────

@pytest.fixture
def slow_probe(monkeypatch):
    """Replace the probe with a slow fake; record concurrency."""
    stats = {"started": 0, "running": 0, "peak": 0, "cancelled": 0}

    async def fake(ip, port, timeout):
        stats["started"] += 1
        stats["running"] += 1
        stats["peak"] = max(stats["peak"], stats["running"])
        try:
            await asyncio.sleep(0.05)
            return {"port": port, "state": "closed", "service": "x",
                    "response_time_ms": 1, "version": None, "banner": None}
        except asyncio.CancelledError:
            stats["cancelled"] += 1
            raise
        finally:
            stats["running"] -= 1

    monkeypatch.setattr(scanner, "_scan_port_async", fake)
    return stats


async def test_pool_size_is_bounded(slow_probe):
    tasks_before = len(asyncio.all_tasks())
    gen = scanner.scan_ports_stream("127.0.0.1", list(range(1, 201)), max_concurrent=10)
    first = await gen.__anext__()
    # 10 workers (+ the current task), not one task per port.
    assert len(asyncio.all_tasks()) - tasks_before <= 10
    rest = await _collect(gen)
    assert len(rest) + 1 == 200 and first["total"] == 200
    assert slow_probe["peak"] <= 10


async def test_closing_the_stream_cancels_all_workers(slow_probe):
    tasks_before = set(asyncio.all_tasks())
    gen = scanner.scan_ports_stream("127.0.0.1", list(range(1, 1001)), max_concurrent=20)
    await gen.__anext__()
    await gen.aclose()
    await asyncio.sleep(0.2)          # give orphans a chance to show up

    leftover = set(asyncio.all_tasks()) - tasks_before
    assert leftover == set()
    assert slow_probe["running"] == 0
    assert slow_probe["started"] < 100          # the other ~900 never started
    assert slow_probe["cancelled"] > 0


async def test_consumer_cancellation_cancels_workers(slow_probe):
    tasks_before = set(asyncio.all_tasks())

    async def consume():
        async for _ in scanner.scan_ports_stream("127.0.0.1", list(range(1, 1001)), max_concurrent=20):
            pass

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.1)
    assert set(asyncio.all_tasks()) - tasks_before == set()
    assert slow_probe["running"] == 0


async def test_worker_crash_does_not_hang(monkeypatch):
    async def broken(ip, port, timeout):
        raise ValueError("boom")

    monkeypatch.setattr(scanner, "_scan_port_async", broken)
    with pytest.raises(ValueError):
        await asyncio.wait_for(_collect(scanner.scan_ports_stream("127.0.0.1", [1, 2, 3])), 2)


# ── Error classification ──────────────────────────────────────────────────────

def _raise(exc):
    async def fake_open_connection(*a, **k):
        raise exc
    return fake_open_connection


@pytest.mark.parametrize("exc,state", [
    (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), "closed"),
    (ConnectionResetError(errno.ECONNRESET, "reset"), "closed"),
    (OSError(errno.EHOSTUNREACH, "no route"), "filtered"),
    (OSError(errno.ENETUNREACH, "net unreachable"), "filtered"),
    (TimeoutError(), "filtered"),
])
async def test_error_states(monkeypatch, exc, state):
    monkeypatch.setattr(asyncio, "open_connection", _raise(exc))
    res = await scanner._scan_port_async("127.0.0.1", 80, 1.0)
    assert res["state"] == state
    assert "error" not in res


async def test_unexpected_oserror_is_labelled(monkeypatch):
    monkeypatch.setattr(asyncio, "open_connection", _raise(OSError(errno.EPROTO, "proto")))
    res = await scanner._scan_port_async("127.0.0.1", 80, 1.0)
    assert res["state"] == "filtered" and res["error"] == "EPROTO"


async def test_emfile_is_retried_not_reported_as_filtered(monkeypatch):
    calls = {"n": 0}

    async def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:
            raise OSError(errno.EMFILE, "Too many open files")
        raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

    monkeypatch.setattr(asyncio, "open_connection", flaky)
    res = await scanner._probe_with_retry("127.0.0.1", 80, 1.0)
    assert res["state"] == "closed" and calls["n"] == 3


async def test_persistent_emfile_aborts_scan(monkeypatch):
    monkeypatch.setattr(asyncio, "open_connection", _raise(OSError(errno.EMFILE, "Too many open files")))
    monkeypatch.setattr(scanner, "_RESOURCE_RETRIES", 2)
    with pytest.raises(scanner.ScanResourceError):
        await _collect(scanner.scan_ports_stream("127.0.0.1", [1, 2], max_concurrent=2))


def test_concurrency_capped_by_fd_limit(monkeypatch):
    import resource
    monkeypatch.setattr(resource, "getrlimit", lambda r: (256, 4096))
    assert scanner.fd_budget() == 256 - scanner._FD_RESERVE
    assert scanner.effective_concurrency(1000) == 128
    assert scanner.effective_concurrency(10) == 10
    monkeypatch.setattr(resource, "getrlimit", lambda r: (50, 4096))
    assert scanner.effective_concurrency(1000) == 1


# ── Slow ("sigiloso") mode ────────────────────────────────────────────────────

async def test_slow_mode_shuffles_and_adds_random_delays(monkeypatch, slow_probe):
    sleeps = []
    real_sleep = asyncio.sleep

    async def spy_sleep(delay, *a, **k):
        sleeps.append(delay)
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", spy_sleep)
    prof = scanner.PROFILES["slow"]
    ports = list(range(1, 41))
    results = await _collect(scanner.scan_ports_stream(
        "127.0.0.1", ports, max_concurrent=prof["max_concurrent"],
        jitter=prof["jitter"], shuffle=prof["shuffle"], rng=random.Random(42),
    ))
    assert sorted(r["port"] for r in results) == ports
    jitter_sleeps = [d for d in sleeps if d >= prof["jitter"][0]]
    assert len(jitter_sleeps) == 40
    assert all(prof["jitter"][0] <= d <= prof["jitter"][1] for d in jitter_sleeps)
    assert len(set(round(d, 3) for d in jitter_sleeps)) > 30      # actually random
    assert slow_probe["peak"] <= prof["max_concurrent"]


async def test_shuffle_changes_probe_order(monkeypatch):
    order = []

    async def record(ip, port, timeout):
        order.append(port)
        return {"port": port, "state": "closed", "service": "x"}

    monkeypatch.setattr(scanner, "_scan_port_async", record)
    ports = list(range(1, 101))
    await _collect(scanner.scan_ports_stream("127.0.0.1", ports, max_concurrent=1,
                                             shuffle=True, rng=random.Random(1)))
    assert sorted(order) == ports and order != ports


def test_slow_profile_is_slow():
    prof = scanner.PROFILES["slow"]
    assert prof["max_concurrent"] <= 5 and prof["jitter"][0] > 0 and prof["shuffle"]
