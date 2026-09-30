"""
limits.py
─────────
Global concurrency caps for expensive operations.

Each heavy operation (port scan, nmap, screenshot, HTTP audit, TLS analysis)
has a process-wide slot count.  When all slots are busy the request is
rejected immediately with HTTP 429 instead of queueing, so one client cannot
pile up unbounded work.

Settings (see settings.py / .env.example):
  LUKITA_MAX_SCANS        concurrent port scans          (default 2)
  LUKITA_MAX_NMAP         concurrent nmap processes      (default 1)
  LUKITA_MAX_SCREENSHOTS  concurrent screenshots         (default 2)
  LUKITA_MAX_AUDITS       concurrent HTTP audits         (default 2)
  LUKITA_MAX_SSL          concurrent TLS analyses        (default 2)
"""

from __future__ import annotations

import settings


class Busy(Exception):
    """All slots for an operation are in use."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Too many concurrent {name} operations; try again later.")
        self.name = name


class SlotLimiter:
    """Non-blocking counting limiter (single event loop, no await inside)."""

    def __init__(self, name: str, setting: str) -> None:
        self.name     = name
        self._setting = setting          # attribute of settings.Settings
        self._in_use  = 0

    @property
    def limit(self) -> int:
        return getattr(settings.get_settings(), self._setting)

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

    async def __aenter__(self) -> SlotLimiter:
        self.acquire()
        return self

    async def __aexit__(self, *exc) -> None:
        self.release()


scans       = SlotLimiter("scan",       "max_scans")
nmap        = SlotLimiter("nmap",       "max_nmap")
screenshots = SlotLimiter("screenshot", "max_screenshots")
audits      = SlotLimiter("audit",      "max_audits")
ssl_checks  = SlotLimiter("ssl",        "max_ssl")

# Upper bounds on request sizes.
MAX_FINGERPRINT_PORTS = 100
MAX_AUDIT_PORTS       = 1000
MAX_CVE_BATCH         = 20


def stats() -> dict[str, dict[str, int]]:
    return {
        lim.name: {"in_use": lim.in_use, "limit": lim.limit}
        for lim in (scans, nmap, screenshots, audits, ssl_checks)
    }
