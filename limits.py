"""
limits.py
─────────
Global concurrency caps for expensive operations.

Each heavy operation (port scan, nmap, screenshot, HTTP audit, TLS analysis)
has a process-wide slot count.  When all slots are busy the request is
rejected immediately with HTTP 429 instead of queueing, so one client cannot
pile up unbounded work.

Environment variables (all optional):
  LUKITA_MAX_SCANS        concurrent port scans          (default 2)
  LUKITA_MAX_NMAP         concurrent nmap processes      (default 1)
  LUKITA_MAX_SCREENSHOTS  concurrent screenshots         (default 2)
  LUKITA_MAX_AUDITS       concurrent HTTP audits         (default 2)
  LUKITA_MAX_SSL          concurrent TLS analyses        (default 2)
"""

from __future__ import annotations

import os


class Busy(Exception):
    """All slots for an operation are in use."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Too many concurrent {name} operations; try again later.")
        self.name = name


class SlotLimiter:
    """Non-blocking counting limiter (single event loop, no await inside)."""

    def __init__(self, name: str, env_var: str, default: int) -> None:
        self.name     = name
        self._env_var = env_var
        self._default = default
        self._in_use  = 0

    @property
    def limit(self) -> int:
        raw = os.getenv(self._env_var, "").strip()
        try:
            value = int(raw) if raw else self._default
        except ValueError:
            value = self._default
        return max(1, value)

    @property
    def in_use(self) -> int:
        return self._in_use

    def try_acquire(self) -> bool:
        if self._in_use >= self.limit:
            return False
        self._in_use += 1
        return True

    def acquire(self) -> None:
        if not self.try_acquire():
            raise Busy(self.name)

    def release(self) -> None:
        self._in_use = max(0, self._in_use - 1)

    async def __aenter__(self) -> "SlotLimiter":
        self.acquire()
        return self

    async def __aexit__(self, *exc) -> None:
        self.release()


scans       = SlotLimiter("scan",       "LUKITA_MAX_SCANS",       2)
nmap        = SlotLimiter("nmap",       "LUKITA_MAX_NMAP",        1)
screenshots = SlotLimiter("screenshot", "LUKITA_MAX_SCREENSHOTS", 2)
audits      = SlotLimiter("audit",      "LUKITA_MAX_AUDITS",      2)
ssl_checks  = SlotLimiter("ssl",        "LUKITA_MAX_SSL",         2)

# Upper bounds on request sizes.
MAX_FINGERPRINT_PORTS = 100
MAX_AUDIT_PORTS       = 1000
MAX_CVE_BATCH         = 20


def stats() -> dict[str, dict[str, int]]:
    return {
        lim.name: {"in_use": lim.in_use, "limit": lim.limit}
        for lim in (scans, nmap, screenshots, audits, ssl_checks)
    }
