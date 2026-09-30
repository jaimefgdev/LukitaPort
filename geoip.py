"""
geoip.py
────────
Optional, fully local GeoIP enrichment.

Disabled by default: scanned addresses are never sent to a third party.
To enable it, download the free MaxMind GeoLite2 databases and point the
environment at them:

  LUKITA_GEOIP_DB       path to GeoLite2-City.mmdb (or GeoLite2-Country.mmdb)
  LUKITA_GEOIP_ASN_DB   optional path to GeoLite2-ASN.mmdb

Lookups are local file reads (``maxminddb``); no network access happens.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Optional

from logging_config import get_logger

logger = get_logger(__name__)

_lock    = threading.Lock()
_readers: dict[str, Any] = {}


def _db_paths() -> tuple[Optional[str], Optional[str]]:
    city = os.getenv("LUKITA_GEOIP_DB", "").strip() or None
    asn  = os.getenv("LUKITA_GEOIP_ASN_DB", "").strip() or None
    return city, asn


def is_enabled() -> bool:
    return _db_paths()[0] is not None


def status() -> dict:
    """Public description of the GeoIP configuration (shown in the UI)."""
    city, asn = _db_paths()
    if city is None:
        return {"enabled": False, "source": None, "asn": False}
    return {
        "enabled": True,
        "source":  f"MaxMind GeoLite2 (local file: {os.path.basename(city)})",
        "asn":     asn is not None,
    }


def _open(path: str):  # noqa: ANN202
    with _lock:
        reader = _readers.get(path)
        if reader is None:
            import maxminddb  # imported lazily: optional dependency
            reader = maxminddb.open_database(path)
            _readers[path] = reader
        return reader


def _name(record: dict, key: str) -> str:
    return ((record.get(key) or {}).get("names") or {}).get("en", "")


def lookup(ip: str) -> dict:
    """Return geo data for ``ip`` from the local databases.  Never raises."""
    city_db, asn_db = _db_paths()
    if city_db is None:
        return {}
    result: dict[str, str] = {}
    try:
        rec = _open(city_db).get(ip) or {}
        subdivisions = rec.get("subdivisions") or [{}]
        result.update({
            "country":      _name(rec, "country"),
            "country_code": (rec.get("country") or {}).get("iso_code", ""),
            "region":       ((subdivisions[0].get("names") or {}).get("en", "")),
            "city":         _name(rec, "city"),
        })
        if asn_db:
            asn = _open(asn_db).get(ip) or {}
            number = asn.get("autonomous_system_number")
            result["asn"] = f"AS{number}" if number else ""
            result["org"] = asn.get("autonomous_system_organization", "")
    except Exception as exc:  # noqa: BLE001
        logger.warning("geoip_lookup_failed", ip=ip, error=str(exc))
        return {}
    return {k: v for k, v in result.items() if v}
