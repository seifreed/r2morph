"""Regression test: the parallel simplifier must serialize shared-r2 access.

Pre-fix, ``_apply_passes_parallel`` submitted ``pass_obj.apply`` directly
to a 3-worker ThreadPool, so all three passes drove the single shared,
non-thread-safe ``self.binary.r2`` duplex pipe concurrently. That data
race can let one worker read another worker's response (silently
corrupting analysis) and churns the BrokenPipe respawn path. The fix
holds a lock so only one worker drives radare2 at a time.

This test fails against the pre-fix code (observed peak concurrency > 1)
and passes after (peak concurrency == 1). Real named doubles only.
"""

from __future__ import annotations

from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier
from tests._doubles.concurrency_probe_binary import (
    ConcurrencyProbeBinary,
    ProbeSimplificationPass,
)


def test_parallel_passes_never_drive_shared_r2_concurrently() -> None:
    binary = ConcurrencyProbeBinary()
    simplifier = IterativeSimplifier(binary)
    simplifier.binary = binary
    simplifier.passes = [
        ProbeSimplificationPass("alpha"),
        ProbeSimplificationPass("beta"),
        ProbeSimplificationPass("gamma"),
    ]
    simplifier.parallel_execution = True

    simplifier._apply_passes_parallel({})

    assert binary.r2.call_count == 3
    assert binary.r2.max_concurrency == 1
