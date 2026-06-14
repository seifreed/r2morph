from r2morph.analysis.symbolic.path_explorer_models import ExplorationStrategy
from r2morph.analysis.symbolic.path_explorer_results import (
    build_opaque_predicates,
    build_vm_handlers,
    collect_exploration_results,
)
from r2morph.analysis.symbolic.path_explorer_techniques import (
    OpaquePredicateDetectionTechnique,
    VMHandlerDetectionTechnique,
)


class _State:
    def __init__(self, constraints: list[str]) -> None:
        self.solver = type("Solver", (), {"constraints": constraints})()


def test_path_explorer_results_contract() -> None:
    vm_technique = VMHandlerDetectionTechnique()
    vm_technique.handler_patterns.add(0x1000)
    opaque_technique = OpaquePredicateDetectionTechnique()
    opaque_technique.opaque_candidates.add(0x2000)
    opaque_technique.branch_outcomes[0x2000] = [True, False]

    result = collect_exploration_results(
        type("Simgr", (), {"found": [_State(["a"])], "deadended": [_State(["b"])]})(),
        ExplorationStrategy.OPAQUE_PREDICATE,
        1.5,
        {
            ExplorationStrategy.VM_HANDLER: vm_technique,
            ExplorationStrategy.OPAQUE_PREDICATE: opaque_technique,
        },
    )

    assert result.execution_time == 1.5
    assert result.opaque_predicates_found == 1
    assert result.constraints_collected == ["a", "b"]

    assert build_vm_handlers(vm_technique)[0]["address"] == 0x1000
    assert build_opaque_predicates(opaque_technique)[0]["sample_count"] == 2
