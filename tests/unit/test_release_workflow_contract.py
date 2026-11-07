"""Regression contracts for release workflow bootstrap ordering."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_validate_release_installs_checker_dependencies_before_running_contract() -> None:
    workflow: dict[str, Any] = yaml.safe_load((_ROOT / ".github" / "workflows" / "release.yml").read_text())
    steps = workflow["jobs"]["validate-release"]["steps"]
    dependency_step = next(
        (index for index, step in enumerate(steps) if step.get("name") == "Install release dependencies"), None
    )
    contract_step = next(
        (index for index, step in enumerate(steps) if step.get("name") == "Validate support contract"), None
    )

    expect(
        dependency_step is not None
        and contract_step is not None
        and dependency_step < contract_step
        and "pip install -r requirements.txt" in steps[dependency_step]["run"]
    )
