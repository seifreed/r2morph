"""Contract tests for binary file locking."""

from __future__ import annotations

from r2morph.core.binary_file_lock import BinaryFileLock
from tests.utils.assertions import expect


def test_binary_file_lock_acquire_release_roundtrip(tmp_path):
    lock = BinaryFileLock(tmp_path / "sample.bin")

    expect(not (lock.is_locked() is not False))
    expect(not (lock.acquire() is not True))
    expect(not (lock.is_locked() is not True))

    lock.release()

    expect(not (lock.is_locked() is not False))
