"""
run.py
──────
Recommended way to start LukitaPort::

    python run.py

Reads LUKITA_HOST (default 127.0.0.1) and LUKITA_PORT (default 8000) and
refuses to start on a non-loopback interface unless LUKITA_API_TOKEN is set
(see security.py).  Runs a single worker: scan slots, caches and the shared
browser are per-process state.
"""

from __future__ import annotations

import os
import sys

import uvicorn

import security


def main() -> int:
    try:
        settings = security.get_settings()   # cached: the app reuses it
    except security.ConfigurationError as exc:
        print(f"LukitaPort: refusing to start — {exc}", file=sys.stderr)
        return 2

    try:
        port = int(os.getenv("LUKITA_PORT", "8000"))
    except ValueError:
        print("LukitaPort: LUKITA_PORT must be an integer", file=sys.stderr)
        return 2

    uvicorn.run(
        "main:app",
        host=settings.bind_host,
        port=port,
        workers=1,
        proxy_headers=False,        # client IPs are used for rate limiting
        server_header=False,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
