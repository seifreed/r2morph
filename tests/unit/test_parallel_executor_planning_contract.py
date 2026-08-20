from r2morph.mutations.parallel_executor_planning import (
    MutationTaskPlan,
    build_task_plans,
    chunk_functions,
)
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY


class _DummyPass:
    def __init__(self, name: str, enabled: bool = True, config: dict[str, object] | None = None) -> None:
        self.name = name
        self.enabled = enabled
        self.config = config or {"key": "value"}


def test_chunk_functions_splits_evenly() -> None:
    functions = [{"addr": 1}, {"addr": 2}, {"addr": 3}, {"addr": 4}, {"addr": 5}]

    chunks = chunk_functions(functions, 2)

    expect(chunks == [[{"addr": 1}, {"addr": 2}], [{"addr": 3}, {"addr": 4}], [{"addr": 5}]])


def test_chunk_functions_rejects_non_positive_chunk_size() -> None:
    try:
        chunk_functions([{"addr": 1}], 0)
    except ValueError as exc:
        expect(not ("chunk_size" not in str(exc)))
    else:
        raise AssertionError("Expected ValueError")


def test_build_task_plans_uses_enabled_passes_and_copies_config() -> None:
    enabled = _DummyPass("enabled", enabled=True, config={"mode": "fast"})
    disabled = _DummyPass("disabled", enabled=False, config={"mode": "slow"})
    functions = [{"addr": 10}, {"addr": 20}, {"addr": 30}]

    plans = build_task_plans([enabled, disabled], functions, 2)

    expect(
        plans
        == [
            MutationTaskPlan(
                pass_instance=enabled,
                **{MUTATION_NAME_KEY: "enabled"},
                function_addresses=[10, 20],
                config={"mode": "fast"},
            ),
            MutationTaskPlan(
                pass_instance=enabled,
                **{MUTATION_NAME_KEY: "enabled"},
                function_addresses=[30],
                config={"mode": "fast"},
            ),
        ]
    )
    expect(plans[0].config is not enabled.config)
