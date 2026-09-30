"""Point 16: ping/nmap subprocesses are always reaped; cancellation propagates.

No real process is spawned: ``asyncio.create_subprocess_exec`` is replaced
by a fake whose behaviour each test controls.
"""

import asyncio

import pytest

import scan_service


class FakeProc:
    def __init__(self, *, ignore_term=False, output=b"", returncode=0, hang=True):
        self.returncode = None
        self.ignore_term = ignore_term
        self.output = output
        self.final_rc = returncode
        self.hang = hang
        self.signals = []
        self._exited = asyncio.Event()

    def terminate(self):
        self.signals.append("TERM")
        if not self.ignore_term:
            self._exit(-15)

    def kill(self):
        self.signals.append("KILL")
        self._exit(-9)

    def _exit(self, rc):
        self.returncode = rc
        self._exited.set()

    async def wait(self):
        await self._exited.wait()
        return self.returncode

    async def communicate(self):
        if self.hang:
            await self._exited.wait()
            return b"", b""
        self._exit(self.final_rc)
        return self.output, b""


@pytest.fixture
def spawn(monkeypatch):
    procs = []

    def install(**kw):
        async def fake_exec(*args, **kwargs):
            p = FakeProc(**kw)
            p.args = args
            procs.append(p)
            return p
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        return procs
    return install


async def test_terminate_escalates_to_kill():
    p = FakeProc(ignore_term=True)
    await scan_service._terminate(p, grace=0.05)
    assert p.signals == ["TERM", "KILL"] and p.returncode == -9


async def test_terminate_graceful():
    p = FakeProc()
    await scan_service._terminate(p, grace=1)
    assert p.signals == ["TERM"] and p.returncode == -15


async def test_terminate_noop_when_exited():
    p = FakeProc()
    p._exit(0)
    await scan_service._terminate(p)
    assert p.signals == []


async def test_ping_success_parses_rtt(spawn):
    procs = spawn(hang=False, output=b"64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.042 ms")
    assert await scan_service._ping_one("127.0.0.1") == {
        "ip": "127.0.0.1", "alive": True, "rtt_ms": 0.042,
    }
    assert procs[0].args[0] == "ping"


async def test_ping_timeout_reaps_process(spawn, monkeypatch):
    procs = spawn(hang=True, ignore_term=True)
    monkeypatch.setattr(scan_service, "_TERMINATE_GRACE", 0.05)
    real_wait_for = asyncio.wait_for

    async def fast_wait_for(aw, timeout):
        return await real_wait_for(aw, min(timeout, 0.05))

    monkeypatch.setattr(asyncio, "wait_for", fast_wait_for)
    assert await scan_service._ping_one("127.0.0.1") is None
    assert procs[0].signals == ["TERM", "KILL"] and procs[0].returncode is not None


async def test_ping_cancellation_propagates_and_reaps(spawn):
    procs = spawn(hang=True)
    task = asyncio.create_task(scan_service._ping_one("127.0.0.1"))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert procs[0].signals == ["TERM"] and procs[0].returncode == -15


async def test_ping_sweep_can_be_cancelled(spawn):
    import ipaddress
    procs = spawn(hang=True)
    hosts = [ipaddress.ip_address(f"127.0.0.{i}") for i in range(1, 11)]
    task = asyncio.create_task(scan_service.ping_sweep(hosts, concurrency=4))
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert procs and all(p.returncode is not None for p in procs)


async def test_nmap_timeout_reaps(spawn, monkeypatch):
    procs = spawn(hang=True, ignore_term=True)
    monkeypatch.setattr(scan_service, "find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(scan_service, "_TERMINATE_GRACE", 0.05)
    real_wait_for = asyncio.wait_for

    async def fast_wait_for(aw, timeout):
        return await real_wait_for(aw, min(timeout, 0.05))

    monkeypatch.setattr(asyncio, "wait_for", fast_wait_for)
    assert await scan_service.run_nmap("127.0.0.1", "22", 1) == {"_error": "nmap_timeout"}
    assert procs[0].signals == ["TERM", "KILL"]


async def test_nmap_cancellation_propagates_and_reaps(spawn, monkeypatch):
    procs = spawn(hang=True)
    monkeypatch.setattr(scan_service, "find_nmap", lambda: "/usr/bin/nmap")
    task = asyncio.create_task(scan_service.run_nmap("127.0.0.1", "22", 30))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert procs[0].returncode == -15
    assert procs[0].args[-1] == "127.0.0.1"          # target is the last argv item
