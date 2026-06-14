"""File collection helpers for binary validation runtime execution."""

from __future__ import annotations

from pathlib import Path


def collect_monitored_files(run_dir: Path, monitored_files: list[str]) -> dict[str, str]:
    """Collect monitored file contents from the run directory."""
    files: dict[str, str] = {}
    for rel_path in monitored_files:
        file_path = run_dir / rel_path
        if file_path.exists() and file_path.is_file():
            try:
                files[rel_path] = file_path.read_bytes().hex()
            except Exception:
                files[rel_path] = ""
    return files
