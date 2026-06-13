"""Regression: ParallelMutationEngine must serialize binary mutation
across pass-worker threads.

ParallelMutationEngine._execute_stage runs each pass's apply() in a
ThreadPoolExecutor. The only guard was BinaryFileLock, but that lock
only coordinates across *processes*: a single shared instance is used
for all threads and its acquire() returns True immediately once
_locked is set, so a second concurrent pass-worker "acquires" it
without any exclusivity and mutates the shared, non-thread-safe
Binary/r2pipe at the same time as the first.

No mocks (CLAUDE.md SS4): two real RecordingMutationPass instances and
a real ConcurrencyRecorder make the peak number of passes inside the
binary-mutation critical section an observable, deterministic value.
"""

from pathlib import Path

from r2morph.core.parallel import ParallelMutationEngine, PassStatus
from tests._doubles.concurrency_recording_mutation_pass import (
    ConcurrencyRecorder,
    PathOnlyBinary,
    RecordingMutationPass,
)


def test_parallel_engine_serializes_binary_mutation(tmp_path: Path) -> None:
    binary_path = tmp_path / "fake.bin"
    binary_path.write_bytes(b"\x7fELF" + b"\x00" * 60)
    binary = PathOnlyBinary(binary_path)

    recorder = ConcurrencyRecorder()
    passes = [
        RecordingMutationPass("pass_a", recorder),
        RecordingMutationPass("pass_b", recorder),
    ]

    engine = ParallelMutationEngine(
        binary,
        max_workers=4,
        use_checkpoints=False,
        use_file_lock=True,
    )
    results = engine.execute(passes, stop_on_error=False)

    assert set(results) == {"pass_a", "pass_b"}
    assert all(r.status == PassStatus.COMPLETED for r in results.values())
    # Both passes land in one dependency-free stage and run concurrently.
    # Without in-process serialization they overlap (max_active == 2).
    assert recorder.max_active == 1
