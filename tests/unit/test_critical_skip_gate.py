"""Regression checks for the stable product smoke skip gate."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from scripts.check_critical_skips import skipped_test_count
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_critical_skip_gate_accepts_junit_report_without_skips(tmp_path: Path) -> None:
    report = tmp_path / "junit.xml"
    report.write_text('<testsuite tests="1"><testcase name="stable" /></testsuite>', encoding="utf-8")

    expect(skipped_test_count(report) == 0)


def test_critical_skip_gate_rejects_junit_report_with_skipped_test(tmp_path: Path) -> None:
    report = tmp_path / "junit.xml"
    report.write_text(
        '<testsuite tests="1"><testcase name="stable"><skipped message="unsupported" /></testcase></testsuite>',
        encoding="utf-8",
    )

    expect(skipped_test_count(report) == 1)


def test_ci_product_smoke_runs_critical_skip_gate() -> None:
    workflow: dict[str, Any] = yaml.safe_load((_ROOT / ".github" / "workflows" / "ci.yml").read_text())
    steps = workflow["jobs"]["product-smoke-tests"]["steps"]
    smoke_step = next(step for step in steps if step.get("name") == "Run product smoke tests")

    expect(
        '--junitxml="$RUNNER_TEMP/stable-product-smoke.xml"' in smoke_step["run"]
        and 'scripts/check_critical_skips.py "$RUNNER_TEMP/stable-product-smoke.xml"' in smoke_step["run"]
    )
