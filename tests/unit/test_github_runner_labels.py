"""Regression checks for supported GitHub-hosted macOS runner labels."""

from __future__ import annotations

from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_ci_matrix_uses_supported_macos_runner_images() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    expect("os: [ubuntu-latest, macos-latest, macos-15, windows-latest]" in workflow and "macos-14" not in workflow)


def test_arm64_differential_uses_current_macos_runner() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    differential_job = workflow.split("  cross-platform-differential:\n", 1)[1].split(
        "  cross-platform-format-windows:\n", 1
    )[0]

    expect("runs-on: macos-latest" in differential_job)


def test_compatibility_docs_name_current_macos_runner() -> None:
    documentation = (_ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8")

    expect("`macos-latest` (currently the `macos-26-arm64` image)" in documentation)
