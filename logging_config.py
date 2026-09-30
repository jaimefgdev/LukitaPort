"""
logging_config.py
─────────────────
Structured JSON logging for LukitaPort.

Every log record is emitted as a single JSON line, making it trivially
ingestible by ELK, Loki, Datadog, or any other log aggregator.

Usage
-----
    from logging_config import get_logger
    logger = get_logger(__name__)
    logger.info("scan_started", target="1.2.3.4", mode="quick")
"""

import json
import logging
import time
from collections.abc import MutableMapping
from typing import Any


class _JSONFormatter(logging.Formatter):
    """Emit each record as a single compact JSON object."""

    _RESERVED = frozenset(
        ("name", "msg", "args", "levelname", "levelno", "pathname",
         "filename", "module", "exc_info", "exc_text", "stack_info",
         "lineno", "funcName", "created", "msecs", "relativeCreated",
         "thread", "threadName", "processName", "process", "message",
         "taskName", "asctime")
    )

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        payload: dict[str, Any] = {
            "ts":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.message,
            "module":  record.module,
            "line":    record.lineno,
        }
        # Attach any extra kwargs passed by the caller
        for key, val in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload[key] = val

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    """
    Call once at application startup (e.g. in main.py lifespan).
    Replaces the root handler with a JSON-streaming one.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler: logging.Handler = root.handlers[0] if root.handlers else logging.StreamHandler()

    handler.setFormatter(_JSONFormatter())
    if handler not in root.handlers:
        root.addHandler(handler)

    # Silence noisy third-party loggers
    for lib in ("httpx", "httpcore", "asyncio", "playwright"):
        logging.getLogger(lib).setLevel(logging.WARNING)


_LOGRECORD_ATTRS = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", None, None))
) | _JSONFormatter._RESERVED


class StructuredLogger(logging.LoggerAdapter):
    """
    Logger adapter that accepts arbitrary keyword arguments as structured
    fields::

        logger.info("scan_start", target="1.2.3.4", mode="quick")

    The stdlib ``Logger`` only accepts ``exc_info``, ``stack_info``,
    ``stacklevel`` and ``extra``; any other keyword raises ``TypeError``.
    This adapter moves the extra keywords into ``extra`` so that
    ``_JSONFormatter`` emits them as top-level JSON keys.
    """

    _PASSTHROUGH = frozenset(("exc_info", "stack_info", "stacklevel", "extra"))

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any],
    ) -> tuple[Any, MutableMapping[str, Any]]:
        fields = {k: kwargs.pop(k) for k in list(kwargs) if k not in self._PASSTHROUGH}
        extra  = dict(kwargs.get("extra") or {})
        for key, val in fields.items():
            # Avoid clobbering LogRecord attributes (would raise KeyError).
            extra[f"field_{key}" if key in _LOGRECORD_ATTRS else key] = val
        kwargs["extra"] = extra
        return msg, kwargs


def get_logger(name: str) -> StructuredLogger:
    """Return a named structured logger (see ``StructuredLogger``)."""
    return StructuredLogger(logging.getLogger(name), {})
