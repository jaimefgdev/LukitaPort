"""Fix 4: the lock files must install on Windows (and every supported OS)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Packages that do not exist for Windows (uvicorn[standard] pulls uvloop).
POSIX_ONLY = {"uvloop"}


def _requirements(name):
    """{package: marker or ''} from a hashed lock file."""
    entries = {}
    for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==\S+(?:\s*;\s*(.*?))?\s*(\\)?$", line)
        if m:
            entries[m.group(1).lower()] = (m.group(2) or "").strip()
    return entries


@pytest.mark.parametrize("lock", ["requirements.txt", "requirements-dev.txt"])
def test_lock_is_universal(lock):
    header = (ROOT / lock).read_text(encoding="utf-8")[:400]
    assert "--universal" in header, f"{lock} must be generated with `uv pip compile --universal`"


@pytest.mark.parametrize("lock", ["requirements.txt", "requirements-dev.txt"])
def test_posix_only_packages_are_excluded_on_windows(lock):
    reqs = _requirements(lock)
    for pkg in POSIX_ONLY & reqs.keys():
        assert "sys_platform != 'win32'" in reqs[pkg], f"{pkg} has no Windows marker in {lock}"


@pytest.mark.parametrize("lock", ["requirements.txt", "requirements-dev.txt"])
def test_markers_evaluate_for_windows_py314(lock):
    """No unconditional requirement is POSIX-only on Windows / Python 3.14."""
    from packaging.markers import Marker

    windows = {"sys_platform": "win32", "os_name": "nt", "platform_system": "Windows",
               "platform_python_implementation": "CPython", "python_version": "3.14",
               "python_full_version": "3.14.0", "implementation_name": "cpython",
               "platform_machine": "AMD64"}
    installed = {pkg for pkg, marker in _requirements(lock).items()
                 if not marker or Marker(marker).evaluate(windows)}
    assert not (installed & POSIX_ONLY)
    assert {"fastapi", "starlette", "uvicorn", "pydantic"} <= installed
