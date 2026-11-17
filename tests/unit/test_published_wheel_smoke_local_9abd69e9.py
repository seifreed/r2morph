"""Keep the bounded installed-wheel smoke evidence tied to its source commit."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/wheel-smoke-local-2026-11-17-9abd69e9.json"
_SOURCE_COMMIT = "9abd69e99ed703e59b7e3c31461104259d3ba448"
_LIMITATION_COUNT = 3
_WHEEL_SHA256 = "09140bfd07b2b7ae9d58baf40d8e45b9af645e0127bd138ebeab3fdf1b1d9b4b"
_SDIST_SHA256 = "633d6980f9d2d0d5b04eeb7b2ea46d813694caff6f31817dfcbffb99ea5773d8"
_TEST_COMMAND = (
    "python -W error -m pytest tests/unit/test_circular_imports.py "
    "tests/unit/test_cli_basic_commands.py::test_cli_version_function "
    "tests/unit/test_public_surface_contract.py --no-cov --tb=short -q"
)
_HOST_PATH = re.compile(r"(?:/Users/|/home/|/private/tmp/|[A-Za-z]:\\Users\\)")


def _report() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_REPORT.read_text(encoding="utf-8")))


def test_published_wheel_smoke_records_hash_bound_artifacts_and_scope() -> None:
    report = _report()
    results = report["installed_wheel_smoke"]

    expect(
        report["source_commit"] == _SOURCE_COMMIT
        and report["artifacts"]["wheel"]["sha256"] == _WHEEL_SHA256
        and report["artifacts"]["sdist"]["sha256"] == _SDIST_SHA256
        and report["build"]["wheel"] == report["build"]["sdist"] == "passed"
        and results["imported_from_installed_wheel"] is True
        and results["tests"] == {"command": _TEST_COMMAND, "passed": 318, "failed": 0, "skipped": 0}
        and len(report["limitations"]) == _LIMITATION_COUNT
    )


def test_published_wheel_smoke_contains_no_local_host_paths() -> None:
    expect(_HOST_PATH.search(_REPORT.read_text(encoding="utf-8")) is None)
