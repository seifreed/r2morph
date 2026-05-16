"""Regression: shared BinaryFileLock must be thread-safe (no fd orphaning).

Bug: _execute_stage shares one BinaryFileLock across ThreadPoolExecutor
pass-workers. acquire() did a non-atomic check-then-open(), so two
threads could each open() the lock file; the later
``self._lock_file = lock_file`` overwrote the first file object,
orphaning it. The orphaned fd was reclaimed only at GC, raising
``Exception ignored while finalizing file '...lock'`` under the
mandated ``pytest -W error`` -- attributed to a random later test
(flaky failures with shifting victims, e.g. /tmp/test.lock).

No mocks (CLAUDE.md s.4): a real BinaryFileLock, real threads, real
file objects. The invariant checked is direct: after a concurrent
acquire/release storm and a GC, there must be zero still-open file
objects pointing at the lock path. Fails pre-fix (orphans remain open),
passes post-fix (serialized acquire opens exactly one).
"""

from __future__ import annotations

import gc
import io
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from r2morph.core.parallel import BinaryFileLock


def _open_files_for(path: str) -> list[io.IOBase]:
    return [
        obj
        for obj in gc.get_objects()
        if isinstance(obj, io.IOBase) and getattr(obj, "name", None) == path and not obj.closed
    ]


def test_shared_lock_under_thread_contention_does_not_orphan_fds(tmp_path: Path) -> None:
    lock = BinaryFileLock(tmp_path / "shared_bin")

    def hammer(_: int) -> None:
        for _ in range(15):
            if lock.acquire():
                lock.release()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(hammer, range(8)))

    lock.release()
    gc.collect()

    leaked = _open_files_for(str(lock.lock_path))
    assert leaked == [], f"orphaned open lock-file objects after contention: {leaked}"
    assert lock._lock_file is None
    assert not lock._locked
