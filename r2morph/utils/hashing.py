"""
Hashing utilities.
"""

import hashlib
from pathlib import Path


def hash_file(path: Path) -> str:
    """
    Calculate SHA256 hash of a file.

    Args:
        path: File path

    Returns:
        SHA256 hex digest
    """
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()
