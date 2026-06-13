"""Regression: ParallelMutator.execute_parallel must return
partial results when the batch exceeds its timeout, not raise.

concurrent.futures.as_completed(fs, timeout=...) raises TimeoutError
from the for-loop itself, not from future.result(). The old code only
caught TimeoutError around future.result() (which has no timeout and
therefore never raises it), so a slow batch let the TimeoutError escape
execute_parallel instead of returning the documented
(records, ParallelStats) tuple with the unfinished tasks counted as
failed.

No mocks (CLAUDE.md SS4): a real Binary over the repo ELF fixture and a
real MutationPass subclass whose apply() sleeps past the timeout.
"""

from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.parallel_executor import ParallelMutator, ParallelStats
from tests._doubles.slow_mutation_pass import SlowMutationPass


def test_execute_parallel_returns_partial_results_on_timeout() -> None:
    executor = ParallelMutator({"timeout": 0.01, "max_workers": 1, "chunk_size": 1})

    with Binary(Path("dataset/elf_x86_64")) as binary:
        binary.analyze()
        records, stats = executor.execute_parallel([SlowMutationPass(sleep_seconds=1.0)], binary)

    assert isinstance(stats, ParallelStats)
    assert isinstance(records, list)
    # The single slow task could not finish within 0.01s, so it must be
    # accounted as failed and no records produced -- without raising.
    assert stats.tasks_failed >= 1
    assert stats.tasks_completed == 0
    assert records == []
