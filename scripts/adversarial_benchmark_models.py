"""Shared option models for adversarial benchmark runners."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BenchmarkOptions:
    """Optional analyzer selection and evidence artifact output settings."""

    tool_names: tuple[str, ...] | None = None
    artifact_directory: Path | None = None
