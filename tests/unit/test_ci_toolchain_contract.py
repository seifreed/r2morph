"""Contracts for tools required by the CI corpus tests."""

from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_ubuntu_ci_installs_clang_for_compiler_generated_corpus() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    ubuntu_setup = workflow.split("Install system dependencies (Ubuntu)", 1)[1].split(
        "Install system dependencies (macOS)", 1
    )[0]

    expect("build-essential clang gcc-arm-linux-gnueabihf" in ubuntu_setup)
