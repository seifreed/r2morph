"""Contracts for tools required by the CI corpus tests."""

import tomllib
from pathlib import Path

import yaml

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


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


def test_ci_runs_unit_suite_on_non_linux_and_python_313_targets() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    cross_platform_step = workflow.split("- name: Run cross-platform unit tests", 1)[1].split(
        "- name: Install build backend for cross-platform wheel smoke", 1
    )[0]

    expect(
        "if: runner.os != 'Linux' || matrix.python-version == '3.13'" in cross_platform_step
        and 'run: python -W error -m pytest -v tests/unit -m "not slow" --no-cov --tb=short' in cross_platform_step
    )


def test_macos_ci_exposes_native_keystone_shared_library() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    macos_setup = workflow.split("Install Keystone shared library (macOS)", 1)[1].split(
        "Install radare2 (Linux/macOS)", 1
    )[0]

    expect("brew install keystone" in macos_setup and "DYLD_LIBRARY_PATH=$(brew --prefix keystone)/lib" in macos_setup)


def test_macos_arm64_ci_installs_rosetta_before_native_macho_smoke() -> None:
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["cross-platform-tests"]["steps"]
    rosetta_index = next(
        index for index, step in enumerate(steps) if step["name"] == "Install Rosetta for native x86-64 Mach-O tests"
    )
    native_smoke_index = next(
        index for index, step in enumerate(steps) if step["name"] == "Run cross-platform package smoke tests"
    )
    rosetta_step = steps[rosetta_index]

    expect(
        rosetta_index < native_smoke_index
        and rosetta_step["if"] == "runner.os == 'macOS'"
        and "sudo softwareupdate --install-rosetta --agree-to-license" in rosetta_step["run"]
        and "arch -x86_64 /usr/bin/true" in rosetta_step["run"]
    )


def test_ubuntu_ci_preserves_floating_point_varargs_repro_on_failure() -> None:
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["cross-platform-tests"]["steps"]
    broad_suite = next(step for step in steps if step["name"] == "Run broad Linux tests with coverage")
    artifact_upload = next(
        step for step in steps if step["name"] == "Upload floating-point varargs ELF after Linux test failure"
    )

    expect(
        '--basetemp="${RUNNER_TEMP}/pytest-$(basename "$test_dir")"' in broad_suite["run"]
        and artifact_upload["if"] == "failure() && runner.os == 'Linux' && matrix.python-version == '3.12'"
        and "test_virtualized_elf_preserves_floating_point_varargs_register_and_stack_abi*"
        in artifact_upload["with"]["path"]
    )
