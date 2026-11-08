"""Contracts for tools required by the CI corpus tests."""

import tomllib
from pathlib import Path

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
