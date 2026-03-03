"""
cache.py
────────
Thread-safe, TTL-aware LRU cache for arbitrary in-process data.

Used primarily to store Playwright screenshots keyed by hostname so that:
  • Old entries expire automatically (TTL, default 10 min).
  • The total number of entries is capped (maxsize).
  • No external dependency — pure stdlib.

Usage
-----
    from cache import ScreenshotCache
    cache = ScreenshotCache(maxsize=100, ttl_seconds=600)
    cache.set("example.com", {"png": b"...", "url": "https://..."})
    data = cache.get("example.com")   # None if expired or missing
    cache.evict_expired()             # call periodically if desired
"""

from __future__ import annotations

import time
from collections import OrderedDict
from threading import Lock
from typing import Generic, Optional, TypeVar

V = TypeVar("V")


class TTLLRUCache(Generic[V]):
    """
    A thread-safe LRU cache where each entry has a time-to-live.

    Eviction strategy
    -----------------
    1. On every ``get`` / ``set``, expired entries discovered incidentally
       are removed.
    2. When ``maxsize`` is exceeded, the *least-recently-used* entry is
       evicted regardless of its TTL.
    3. ``evict_expired()`` performs a full sweep (call from a background task).
    """

    def __init__(self, maxsize: int = 200, ttl_seconds: int = 600) -> None:
        if maxsize < 1:
            raise ValueError("maxsize must be ≥ 1")
        self._maxsize = maxsize
        self._ttl     = ttl_seconds
        # OrderedDict preserves insertion / access order for LRU
        self._store: OrderedDict[str, tuple[V, float]] = OrderedDict()
        self._lock  = Lock()

    # ── Public interface ──────────────────────────────────────────────────────

    def get(self, key: str) -> Optional[V]:
        with self._lock:
            if key not in self._store:
                return None
            value, expires_at = self._store[key]
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            # Move to end → most-recently-used
            self._store.move_to_end(key)
            return value

    def set(self, key: str, value: V) -> None:
        expires_at = time.monotonic() + self._ttl
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, expires_at)
            # Evict LRU entries until within maxsize
            while len(self._store) > self._maxsize:
                self._store.popitem(last=False)

    def delete(self, key: str) -> bool:
        with self._lock:
            return self._store.pop(key, None) is not None

    def evict_expired(self) -> int:
        """Remove all expired entries.  Returns the number removed."""
        now = time.monotonic()
        with self._lock:
            expired = [k for k, (_, exp) in self._store.items() if now > exp]
            for k in expired:
                del self._store[k]
        return len(expired)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    # ── Introspection ─────────────────────────────────────────────────────────

    @property
    def size(self) -> int:
        return len(self._store)

    @property
    def maxsize(self) -> int:
        return self._maxsize

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def stats(self) -> dict[str, int]:
        now = time.monotonic()
        with self._lock:
            total   = len(self._store)
            expired = sum(1 for _, (_, exp) in self._store.items() if now > exp)
        return {
            "size":       total,
            "expired":    expired,
            "live":       total - expired,
            "maxsize":    self._maxsize,
            "ttl_seconds": self._ttl,
        }


# ── Application-level singletons ──────────────────────────────────────────────

ScreenshotData = dict  # {"png": bytes, "url": str, "ts": float}

#: Global screenshot cache — 100 entries max, 10-minute TTL
screenshot_cache: TTLLRUCache[ScreenshotData] = TTLLRUCache(
    maxsize=100,
    ttl_seconds=600,
)
