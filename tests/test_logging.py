"""Point 1: structured logging must accept keyword fields."""

import io
import json
import logging

import pytest

from logging_config import _JSONFormatter, configure_logging, get_logger


@pytest.fixture
def json_stream():
    stream  = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(_JSONFormatter())
    logger  = logging.getLogger("lukita.test")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield stream
    finally:
        logger.removeHandler(handler)


def _records(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_keyword_fields_become_json_keys(json_stream):
    log = get_logger("lukita.test")
    log.info("scan_start", target="127.0.0.1", port_count=30)
    (rec,) = _records(json_stream)
    assert rec["msg"] == "scan_start"
    assert rec["target"] == "127.0.0.1"
    assert rec["port_count"] == 30
    assert rec["level"] == "INFO"


def test_reserved_names_do_not_crash(json_stream):
    log = get_logger("lukita.test")
    # "name", "module" and "message" are LogRecord attributes; passing them
    # straight into ``extra`` would raise KeyError.
    log.warning("evt", name="x", module="y", message="z")
    (rec,) = _records(json_stream)
    assert rec["field_name"] == "x"
    assert rec["field_module"] == "y"
    assert rec["field_message"] == "z"


def test_exc_info_and_extra_still_work(json_stream):
    log = get_logger("lukita.test")
    try:
        raise ValueError("boom")
    except ValueError:
        log.error("failed", exc_info=True, extra={"a": 1}, b=2)
    (rec,) = _records(json_stream)
    assert rec["a"] == 1 and rec["b"] == 2
    assert "ValueError: boom" in rec["exc"]


def test_caller_location_is_the_call_site(json_stream):
    get_logger("lukita.test").info("where")
    (rec,) = _records(json_stream)
    assert rec["module"] == "test_logging"


def test_all_levels_accept_fields_after_configure_logging():
    root = logging.getLogger()
    old_level, old_handlers = root.level, list(root.handlers)
    try:
        configure_logging("DEBUG")
        log = get_logger("lukita.levels")
        for method in ("debug", "info", "warning", "error", "critical"):
            getattr(log, method)("evt", key="value")
    finally:
        root.setLevel(old_level)
        root.handlers[:] = old_handlers
