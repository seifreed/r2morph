"""Ensure CI fetches history needed to validate human review signoffs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from tests.utils.assertions import expect

_CI_WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
_HISTORY_DEPENDENT_JOBS = ("unit-tests", "cross-platform-tests")


def test_signoff_test_jobs_fetch_full_git_history() -> None:
    workflow: dict[str, Any] = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]

    expect(
        all(
            next(step for step in jobs[job]["steps"] if step.get("uses") == "actions/checkout@v5")["with"][
                "fetch-depth"
            ]
            == 0
            for job in _HISTORY_DEPENDENT_JOBS
        )
    )
