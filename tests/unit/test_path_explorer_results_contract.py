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
from tests.utils.assertions import expect

_EXPECTED_BUILD_OPAQUE_PREDICATES_OPAQUE_TECHNIQUE_0_SA_2 = 2
_EXPECTED_BUILD_VM_HANDLERS_VM_TECHNIQUE_0_ADDRESS_4096 = 0x1000
_EXPECTED_RESULT_EXECUTION_TIME_1_5 = 1.5


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

    expect(result.execution_time == _EXPECTED_RESULT_EXECUTION_TIME_1_5)
    expect(result.opaque_predicates_found == 1)
    expect(result.constraints_collected == ["a", "b"])

    expect(build_vm_handlers(vm_technique)[0]["address"] == _EXPECTED_BUILD_VM_HANDLERS_VM_TECHNIQUE_0_ADDRESS_4096)
    expect(
        build_opaque_predicates(opaque_technique)[0]["sample_count"]
        == _EXPECTED_BUILD_OPAQUE_PREDICATES_OPAQUE_TECHNIQUE_0_SA_2
    )
