"""Contract tests for binary file locking."""

from __future__ import annotations

from r2morph.core.binary_file_lock import BinaryFileLock


def test_binary_file_lock_acquire_release_roundtrip(tmp_path):
    lock = BinaryFileLock(tmp_path / "sample.bin")

    assert lock.is_locked() is False
    assert lock.acquire() is True
    assert lock.is_locked() is True

    lock.release()

    assert lock.is_locked() is False
