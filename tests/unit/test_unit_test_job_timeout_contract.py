"""Regression contract for bounded unit-test CI execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_UNIT_TEST_TIMEOUT_MINUTES = 30


def test_unit_test_job_has_thirty_minute_timeout() -> None:
    workflow: dict[str, Any] = yaml.safe_load((_ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job = workflow["jobs"]["unit-tests"]

    expect(job.get("timeout-minutes") == _UNIT_TEST_TIMEOUT_MINUTES)
