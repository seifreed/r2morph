"""Regression coverage for the supported dependency installation contract."""

from __future__ import annotations

import tomllib
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_supported_dependency_manifests_avoid_unavailable_optional_packages() -> None:
    requirements = (_ROOT / "requirements.txt").read_text(encoding="utf-8")
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    optional_dependencies = project["project"]["optional-dependencies"]
    optional_text = "\n".join(dependency for group in optional_dependencies.values() for dependency in group)

    expect("triton-library" not in requirements and "triton-library" not in optional_text)
