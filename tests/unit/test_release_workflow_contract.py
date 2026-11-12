"""Regression contracts for release workflow bootstrap ordering."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_EXPECTED_PUBLIC_SURFACE_CONTRACT_WORKFLOW_OCCURRENCES = 2


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


def test_stable_readiness_gate_runs_before_release_build_and_publish() -> None:
    workflow: dict[str, Any] = yaml.safe_load((_ROOT / ".github" / "workflows" / "release.yml").read_text())
    validation_steps = workflow["jobs"]["validate-release"]["steps"]
    support_contract_step = next(step for step in validation_steps if step.get("name") == "Validate support contract")
    green_ci_step = next(step for step in validation_steps if step.get("name") == "Require green CI for release commit")

    expect(
        "python scripts/check_release_contract.py" in support_contract_step["run"]
        and validation_steps.index(support_contract_step) < validation_steps.index(green_ci_step)
        and workflow["jobs"]["build"]["needs"] == "validate-release"
        and "validate-release" in workflow["jobs"]["publish-pypi"]["needs"]
        and "validate-release" in workflow["jobs"]["create-release"]["needs"]
    )


def test_release_artifacts_are_attested_before_pypi_publish() -> None:
    workflow: dict[str, Any] = yaml.safe_load((_ROOT / ".github" / "workflows" / "release.yml").read_text())
    jobs = workflow["jobs"]
    attest = jobs["attest"]
    attestation_step = next(step for step in attest["steps"] if step.get("name") == "Attest release artifacts")

    expect(
        attest["needs"] == ["validate-release", "build", "test"]
        and attest["permissions"]["attestations"] == "write"
        and attest["permissions"]["id-token"] == "write"
        and attestation_step["uses"] == "actions/attest-build-provenance@v4"
        and "attest" in jobs["publish-pypi"]["needs"]
        and "Attest release artifacts" not in [step.get("name") for step in jobs["create-release"]["steps"]]
    )


def test_installed_wheel_jobs_run_the_public_api_and_cli_contract() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    expect(
        workflow.count("tests/unit/test_public_surface_contract.py")
        == _EXPECTED_PUBLIC_SURFACE_CONTRACT_WORKFLOW_OCCURRENCES
    )


def test_release_wheel_review_contract_reads_source_without_shadowing_installed_package() -> None:
    workflow: dict[str, Any] = yaml.safe_load((_ROOT / ".github" / "workflows" / "release.yml").read_text())
    test_steps = workflow["jobs"]["test"]["steps"]
    run_step = next(step for step in test_steps if step.get("name") == "Run tests against installed wheel")
    run_script = run_step["run"]

    expect(
        'mkdir -p "$test_root/r2morph/mutations"' in run_script
        and 'cp r2morph/mutations/code_virtualization.py "$test_root/r2morph/mutations/"' in run_script
        and "r2morph/__init__.py" not in run_script
    )
