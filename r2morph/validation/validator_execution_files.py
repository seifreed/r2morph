"""File collection helpers for binary validation runtime execution."""

from __future__ import annotations

from pathlib import Path


def collect_monitored_files(run_dir: Path, monitored_files: list[str]) -> dict[str, str]:
    """Collect monitored file contents from the run directory."""
    root = run_dir.resolve()
    files: dict[str, str] = {}
    for rel_path in monitored_files:
        if not isinstance(rel_path, str) or not rel_path:
            raise ValueError("monitored file path must be a non-empty relative path")
        relative_path = Path(rel_path)
        if relative_path.is_absolute():
            raise ValueError("monitored file path must stay within the runtime directory")
        try:
            file_path = (root / relative_path).resolve()
            file_path.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            raise ValueError("monitored file path must stay within the runtime directory") from None
        if file_path.exists() and file_path.is_file():
            try:
                files[rel_path] = file_path.read_bytes().hex()
            except OSError:
                raise ValueError("failed to read a monitored runtime file") from None
    return files
