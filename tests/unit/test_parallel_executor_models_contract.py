from __future__ import annotations

from r2morph.mutations.parallel_executor_models import MutationResult, MutationTask, ParallelStats
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY


def test_parallel_executor_models_contract() -> None:
    task = MutationTask(**{MUTATION_NAME_KEY: "demo"}, pass_instance=object())
    result = MutationResult()
    stats = ParallelStats()

    expect(task.function_addresses == [])
    expect(result.records == [])
    expect(stats.worker_count == 0)
