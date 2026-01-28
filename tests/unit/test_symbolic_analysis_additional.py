from pathlib import Path

import z3

from r2morph.core.binary import Binary
from r2morph.analysis.cfg import ControlFlowGraph, BasicBlock
from r2morph.analysis.symbolic.angr_bridge import AngrBridge
from r2morph.analysis.symbolic.path_explorer import (
    PathExplorer,
    ExplorationStrategy,
    VMHandlerDetectionTechnique,
    OpaquePredicateDetectionTechnique,
)
from r2morph.analysis.symbolic.state_manager import StateManager, StateSchedulingStrategy
from r2morph.analysis.symbolic.constraint_solver import ConstraintSolver, MBAExpression


def _load_binary():
    binary_path = Path("dataset/elf_x86_64")
    bin_obj = Binary(binary_path)
    bin_obj.__enter__()
    bin_obj.analyze()
    return bin_obj


def test_angr_bridge_boundaries_and_cleanup():
    bin_obj = _load_binary()
    try:
        bridge = AngrBridge(bin_obj)
        project = bridge.angr_project

        start, end = bridge.get_function_boundaries(project.entry)
        assert start == project.entry
        assert end > start

        missing_addr = project.entry + 0x1234
        fallback_start, fallback_end = bridge.get_function_boundaries(missing_addr)
        assert fallback_start == missing_addr
        assert fallback_end == missing_addr + 0x100

        cfg = ControlFlowGraph(function_address=project.entry, function_name="entry")
        cfg.add_block(BasicBlock(address=project.entry, size=1))
        bridge.convert_r2_cfg_to_angr(cfg)
        assert isinstance(bridge.angr_project, type(project))

        bridge.synchronize_analysis_results()
        bridge.cleanup()
        assert bridge._r2_to_angr_mapping == {}
        assert bridge._angr_to_r2_mapping == {}
    finally:
        bin_obj.__exit__(None, None, None)


def test_state_manager_scheduling_and_stats():
    bin_obj = _load_binary()
    try:
        bridge = AngrBridge(bin_obj)
        project = bridge.angr_project
        state_a = project.factory.blank_state(addr=project.entry)
        state_b = project.factory.blank_state(addr=project.entry + 1)
        state_c = project.factory.blank_state(addr=project.entry + 2)

        manager = StateManager(max_states=3, scheduling_strategy=StateSchedulingStrategy.COVERAGE_GUIDED)
        id_a = manager.add_state(state_a, priority=0.1)
        id_b = manager.add_state(state_b, priority=0.2)
        id_c = manager.add_state(state_c, priority=0.3)

        manager.state_metrics[id_a].coverage_new_blocks = 3
        manager.state_metrics[id_a].depth = 1
        manager.state_metrics[id_b].coverage_new_blocks = 1
        manager.state_metrics[id_b].depth = 0
        manager.state_metrics[id_c].coverage_new_blocks = 0
        manager.state_metrics[id_c].depth = 0

        next_state = manager.get_next_state()
        assert next_state is not None
        assert next_state[0] == id_a

        manager.scheduling_strategy = StateSchedulingStrategy.DEPTH_FIRST
        assert manager.get_next_state()[0] == id_a

        manager.scheduling_strategy = StateSchedulingStrategy.BREADTH_FIRST
        assert manager.get_next_state()[0] in {id_b, id_c}

        manager.scheduling_strategy = StateSchedulingStrategy.RANDOM
        assert manager.get_next_state()[0] in {id_a, id_b, id_c}

        priority_manager = StateManager(max_states=3, scheduling_strategy=StateSchedulingStrategy.PRIORITY_BASED)
        p1 = priority_manager.add_state(state_a, priority=0.1)
        p2 = priority_manager.add_state(state_b, priority=2.0)
        assert priority_manager.get_next_state()[0] == p2
        assert p1 in priority_manager.active_states

        stats = manager.get_statistics()
        assert stats["active_states"] == 3
        assert stats["states_created"] == 3

        manager.cleanup()
        assert manager.get_statistics()["active_states"] == 0
    finally:
        bin_obj.__exit__(None, None, None)


def test_constraint_solver_expression_parsing_and_opaque_detection():
    solver = ConstraintSolver(timeout=1)

    equiv = solver.check_semantic_equivalence("x + 1", "1 + x", {"x"})
    if equiv.solver_used == "z3":
        assert equiv.satisfiable is True

    not_equiv = solver.check_semantic_equivalence("x + 1", "x + 2", {"x"})
    if not_equiv.solver_used == "z3":
        assert not_equiv.satisfiable is False

    mba = MBAExpression(expression="x ^ x", variables={"x"}, bit_width=8)
    mba_result = solver.simplify_mba_expression(mba)
    if mba_result.solver_used == "z3":
        assert mba_result.satisfiable
        assert mba_result.simplified_expression is not None

    opaque = solver.detect_opaque_predicates([z3.BoolVal(True), z3.BoolVal(False)])
    if solver.get_solver_statistics().get("queries_solved", 0) >= 0:
        assert len(opaque) >= 1


def test_path_explorer_technique_tracking_and_results():
    bin_obj = _load_binary()
    try:
        bridge = AngrBridge(bin_obj)
        explorer = PathExplorer(bridge)
        project = bridge.angr_project

        state = project.factory.blank_state(addr=project.entry)
        simgr = project.factory.simulation_manager(state)

        vm_technique = VMHandlerDetectionTechnique()
        vm_technique.step(simgr)
        vm_score = vm_technique._score_vm_likelihood(state)
        assert isinstance(vm_score, float)

        opaque_technique = OpaquePredicateDetectionTechnique()
        simgr.step()
        stepped_state = simgr.active[0]
        for _ in range(5):
            stepped_state.history.jump_kind = "Ijk_Conditional"
            stepped_state.history.jumpkind = "Ijk_Conditional"
            opaque_technique._track_branch_outcomes(stepped_state)

        assert stepped_state.history.addr in opaque_technique.opaque_candidates

        explorer.exploration_techniques[ExplorationStrategy.OPAQUE_PREDICATE] = opaque_technique
        predicates = explorer.detect_opaque_predicates(stepped_state.history.addr)
        assert predicates
        assert predicates[0]["sample_count"] >= 1
    finally:
        bin_obj.__exit__(None, None, None)
