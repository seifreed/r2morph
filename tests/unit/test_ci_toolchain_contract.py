"""Contracts for tools required by the CI corpus tests."""

import tomllib
from pathlib import Path

import yaml
from packaging.requirements import Requirement

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_INTEGRATION_REPRO_RETENTION_DAYS = 5
_EXPECTED_ANGR_OPTIONAL_EXTRA_COUNT = 3


def test_ubuntu_ci_installs_clang_for_compiler_generated_corpus() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    ubuntu_setup = workflow.split("Install system dependencies (Ubuntu)", 1)[1].split(
        "Install system dependencies (macOS)", 1
    )[0]

    expect("build-essential clang gcc-arm-linux-gnueabihf" in ubuntu_setup)


def test_unicorn_is_unconditionally_installed_by_test_extras() -> None:
    requirements = (_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    optional_dependencies = project["project"]["optional-dependencies"]
    expected = ["unicorn>=2.0.0"]

    unicorn_requirements = [line for line in requirements if line.lower().startswith("unicorn")]
    unicorn_extras = [
        dependency
        for extra in ("dev", "devirtualization", "all")
        for dependency in optional_dependencies[extra]
        if dependency.lower().startswith("unicorn")
    ]

    expect(unicorn_requirements == expected and unicorn_extras == expected * 3)


def test_ubuntu_ci_dependency_audit_allows_network_latency_without_skipping_audit() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    expect("run: pip-audit --timeout 60" in workflow)


def test_ci_runs_unit_suite_on_non_linux_and_non_312_targets() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    cross_platform_step = workflow.split("- name: Run cross-platform unit tests", 1)[1].split(
        "- name: Install build backend for cross-platform wheel smoke", 1
    )[0]

    expect(
        "if: runner.os != 'Linux' || matrix.python-version != '3.12'" in cross_platform_step
        and 'run: python -W error -m pytest -v tests/unit -m "not slow" --no-cov --tb=short -o faulthandler_timeout=60'
        in cross_platform_step
    )


def test_python_314_is_declared_and_runs_cross_platform_ci() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    matrix = workflow["jobs"]["cross-platform-tests"]["strategy"]["matrix"]

    expect(
        project["requires-python"] == ">=3.12,<3.15"
        and "Programming Language :: Python :: 3.14" in project["classifiers"]
        and "3.14" in matrix["python-version"]
    )


def test_macos_ci_exposes_native_keystone_shared_library() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    macos_setup = workflow.split("Install Keystone shared library (macOS)", 1)[1].split(
        "Install radare2 (Linux/macOS)", 1
    )[0]

    expect("brew install keystone" in macos_setup and "DYLD_LIBRARY_PATH=$(brew --prefix keystone)/lib" in macos_setup)


def test_macos_native_macho_smoke_uses_intel_runner_without_rosetta() -> None:
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["cross-platform-tests"]
    steps = job["steps"]

    expect(
        "macos-latest" in job["strategy"]["matrix"]["os"]
        and "macos-15-intel" in job["strategy"]["matrix"]["os"]
        and not any("Rosetta" in step["name"] for step in steps)
    )


def test_angr_optional_dependencies_skip_intel_macos_until_native_build_is_supported() -> None:
    requirements = (_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    requirement_lines = [line for line in requirements if line.startswith("angr>=")]
    extras = project["project"]["optional-dependencies"]
    extra_requirements = [
        dependency
        for name in ("enhanced", "syntia", "all")
        for dependency in extras[name]
        if dependency.startswith("angr>=")
    ]
    marker_values = {
        "platform_system": "Darwin",
        "platform_machine": "x86_64",
        "python_version": "3.12",
    }

    expect(
        len(requirement_lines) == 1
        and len(extra_requirements) == _EXPECTED_ANGR_OPTIONAL_EXTRA_COUNT
        and all(not Requirement(line).marker.evaluate(marker_values) for line in requirement_lines)
        and all(not Requirement(line).marker.evaluate(marker_values) for line in extra_requirements)
        and all(
            Requirement(line).marker.evaluate({**marker_values, "platform_machine": "arm64"})
            for line in requirement_lines + extra_requirements
        )
        and all(
            Requirement(line).marker.evaluate({**marker_values, "platform_system": "Linux"})
            for line in requirement_lines + extra_requirements
        )
        and all(
            not Requirement(line).marker.evaluate({**marker_values, "platform_system": "Windows"})
            for line in requirement_lines + extra_requirements
        )
    )


def test_ubuntu_ci_preserves_floating_point_varargs_repro_on_failure() -> None:
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["cross-platform-tests"]["steps"]
    broad_suite = next(step for step in steps if step["name"] == "Run broad Linux tests with coverage")
    artifact_upload = next(
        step for step in steps if step["name"] == "Upload floating-point varargs repro files after Linux test failure"
    )

    expect(
        '--basetemp="${RUNNER_TEMP}/pytest-$(basename "$test_dir")"' in broad_suite["run"]
        and artifact_upload["if"] == "failure() && runner.os == 'Linux' && matrix.python-version == '3.12'"
        and "pytest-integration/**/test_virtualized_elf_preserves*/floating_point_varargs*"
        in artifact_upload["with"]["path"]
    )


def test_integration_ci_preserves_clang_switch_table_repro_on_failure() -> None:
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["integration-tests"]["steps"]
    integration_run = next(step for step in steps if step["name"] == "Run integration tests")
    artifact_upload = next(
        step for step in steps if step["name"] == "Upload Clang switch-table repro files after integration failure"
    )

    expect(
        '--basetemp="${RUNNER_TEMP}/pytest-integration"' in integration_run["run"]
        and artifact_upload["if"] == "failure()"
        and artifact_upload["with"]["path"] == "${{ runner.temp }}/pytest-integration/test_vm_semantic_campaign*"
        and artifact_upload["with"]["retention-days"] == _INTEGRATION_REPRO_RETENTION_DAYS
    )


def test_long_campaign_workflows_use_distinct_intended_concurrency() -> None:
    differential = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    )["concurrency"]
    adversarial = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")
    )["concurrency"]

    expect(
        differential["cancel-in-progress"] is False
        and "${{ github.run_id }}" in differential["group"]
        and adversarial["cancel-in-progress"] is False
        and adversarial["group"] == "adversarial-benchmark-${{ github.ref }}"
    )
