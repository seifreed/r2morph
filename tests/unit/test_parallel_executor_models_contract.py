from __future__ import annotations

from r2morph.mutations.parallel_executor_models import MutationResult, MutationTask, ParallelStats


def test_parallel_executor_models_contract() -> None:
    task = MutationTask(pass_name="demo", pass_instance=object())
    result = MutationResult()
    stats = ParallelStats()

    assert task.function_addresses == []
    assert result.records == []
    assert stats.worker_count == 0
