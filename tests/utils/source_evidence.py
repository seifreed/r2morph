"""Helpers for verifying immutable source references in published evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path

from git import Repo


def source_script_sha256_at_commit(repository_root: Path, commit: str, source_path: str) -> str:
    """Hash a source file from the Git revision that produced its evidence."""
    _blob_sha, _object_type, size, stream = Repo(repository_root).git.stream_object_data(f"{commit}:{source_path}")
    return hashlib.sha256(stream.read(size)).hexdigest()
