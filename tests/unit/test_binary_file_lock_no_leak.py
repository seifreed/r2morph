"""Regression test: BinaryFileLock must not leak its lock file.

Bug: BinaryFileLock.acquire() opens the lock file, but release() only
closed it inside an ``if self._locked:`` block, and there was no
finalizer. A partial/failed acquire, a double release, or an abandoned
lock therefore kept the fd open until GC finalized it, raising
``Exception ignored while finalizing file '/tmp/...lock'`` -- fatal
under the mandated ``pytest -W error`` and attributed to whatever
unrelated test triggered the GC (flaky failures with shifting victims).

No mocks (CLAUDE.md s.4): a real BinaryFileLock on a real temp path.
"""

from __future__ import annotations

import gc
from pathlib import Path

from r2morph.core.parallel import BinaryFileLock


def test_release_closes_lock_file_even_if_not_locked(tmp_path: Path) -> None:
    lock = BinaryFileLock(tmp_path / "bin")
    assert lock.acquire()
    lock_file = lock._lock_file
    assert lock_file is not None and not lock_file.closed

    # Arrange the exact buggy state: file opened, lock bookkeeping says
    # "not held" (a partial/failed acquire). release() must still close.
    lock._locked = False
    lock.release()

    assert lock_file.closed, "release() leaked the lock file when not _locked"


def test_abandoned_lock_does_not_leak_fd(tmp_path: Path) -> None:
    lock = BinaryFileLock(tmp_path / "bin2")
    assert lock.acquire()
    lock_file = lock._lock_file
    assert lock_file is not None and not lock_file.closed

    # Abandon the lock without release()/__exit__.
    del lock
    gc.collect()

    assert lock_file.closed, "abandoned BinaryFileLock leaked its fd (no __del__)"


def test_double_release_is_safe(tmp_path: Path) -> None:
    lock = BinaryFileLock(tmp_path / "bin3")
    assert lock.acquire()
    lock.release()
    # Must not raise and must remain closed/clean.
    lock.release()
    assert lock._lock_file is None
