"""Regression: a pass's pre-state checkpoint and its mutation must be
mutually exclusive with other pass-worker threads.

_save_checkpoint does shutil.copy2(self.binary.path, ...) (reading the
whole shared binary) and was called outside the in-process
binary-mutation lock. So while one worker held the lock inside
pass_obj.apply (mutating the shared binary), another worker's
_save_checkpoint could copy that same binary file mid-write -- a torn
checkpoint that a later rollback would restore.

No mocks (CLAUDE.md SS4): a real ProbeBinary whose .path getter (read
by _save_checkpoint) and a real CriticalSectionPass.apply both occupy
the binary for a window; a thread-safe recorder reports the peak number
of workers in that binary critical section at once.
"""

from pathlib import Path

from r2morph.core.parallel import ParallelMutationEngine, PassStatus
from tests._doubles.checkpoint_race_doubles import (
    BinaryAccessRecorder,
    CriticalSectionPass,
    ProbeBinary,
)


def test_checkpoint_and_apply_are_mutually_exclusive(tmp_path: Path) -> None:
    binary_path = tmp_path / "fake.bin"
    binary_path.write_bytes(b"\x7fELF" + b"\x00" * 60)

    recorder = BinaryAccessRecorder()
    binary = ProbeBinary(binary_path, recorder)

    passes = [CriticalSectionPass(f"pass_{i}", recorder) for i in range(4)]

    engine = ParallelMutationEngine(
        binary,
        max_workers=4,
        use_checkpoints=True,
        use_file_lock=False,
    )
    results = engine.execute(passes, stop_on_error=False)

    assert set(results) == {f"pass_{i}" for i in range(4)}
    assert all(r.status == PassStatus.COMPLETED for r in results.values())
    # Pre-fix: _save_checkpoint windows run outside the lock and overlap
    # each other / apply windows -> max_active >= 2. Post-fix: snapshot
    # and apply are one locked critical section -> max_active == 1.
    assert recorder.max_active == 1
