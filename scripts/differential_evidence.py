"""Helpers for collecting evidence files downloaded from GitHub Actions."""

from __future__ import annotations

from pathlib import Path


def require_evidence_files(root: str | Path, expected_count: int) -> list[Path]:
    """Find evidence files whether one artifact is flattened or many are nested."""
    directory = Path(root)
    paths = sorted(path for path in directory.rglob("*") if path.is_file())
    if len(paths) != expected_count:
        raise ValueError(f"expected {expected_count} evidence files for {directory}, found {len(paths)}")
    return paths
