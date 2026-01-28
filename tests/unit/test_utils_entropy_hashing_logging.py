from __future__ import annotations

from pathlib import Path

from r2morph.utils.entropy import calculate_entropy, calculate_file_entropy
from r2morph.utils.hashing import hash_file
from r2morph.utils.logging import setup_logging


def test_entropy_calculations(tmp_path: Path) -> None:
    assert calculate_entropy(b"") == 0.0
    assert calculate_entropy(b"\x00" * 16) == 0.0
    assert calculate_entropy(b"\x00\x01" * 8) > 0.0

    sample = tmp_path / "entropy.bin"
    sample.write_bytes(b"\x00\x01" * 8)
    assert calculate_file_entropy(sample) > 0.0


def test_hash_file(tmp_path: Path) -> None:
    sample = tmp_path / "hash.bin"
    sample.write_bytes(b"r2morph")
    digest = hash_file(sample)
    assert len(digest) == 64


def test_setup_logging(tmp_path: Path) -> None:
    log_path = tmp_path / "r2morph.log"
    setup_logging("DEBUG", log_file=str(log_path))
    assert log_path.exists()
