from __future__ import annotations

from r2morph.core.parallel_planner import PassResult, PassStatus
from r2morph.core.parallel_stage_execution import execute_stage
from r2morph.protocols import MutationPassProtocol
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY


class _Pass:
    def __init__(self, name: str) -> None:
        self.name = name


def test_parallel_stage_execution_runs_known_passes() -> None:
    seen: list[str] = []

    def execute_pass(pass_obj: MutationPassProtocol, progress_callback):
        seen.append(pass_obj.name)
        return PassResult(**{MUTATION_NAME_KEY: pass_obj.name}, status=PassStatus.COMPLETED)

    results = execute_stage(
        ["one", "missing", "two"],
        [_Pass("one"), _Pass("two")],
        max_workers=2,
        execute_pass=execute_pass,
        progress_callback=None,
    )

    expect(set(results) == {"one", "two"})
    expect(all(result.status == PassStatus.COMPLETED for result in results.values()))
    expect(sorted(seen) == ["one", "two"])
