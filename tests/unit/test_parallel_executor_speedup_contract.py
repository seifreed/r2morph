from __future__ import annotations

from r2morph.mutations.parallel_executor_speedup import estimate_parallel_speedup


class _Pass:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled


def test_parallel_executor_speedup_contract() -> None:
    speedup = estimate_parallel_speedup(
        [_Pass(True), _Pass(False), _Pass(True)],
        function_count=20,
        max_workers=4,
        chunk_size=5,
    )

    assert speedup > 1.0


def test_parallel_executor_speedup_contract_handles_no_enabled_passes() -> None:
    speedup = estimate_parallel_speedup(
        [_Pass(False)],
        function_count=20,
        max_workers=4,
        chunk_size=5,
    )

    assert speedup == 1.0
