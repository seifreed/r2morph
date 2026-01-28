from pathlib import Path

import importlib.util
import pytest
import claripy

if importlib.util.find_spec("angr") is None:
    pytest.skip("angr not available", allow_module_level=True)

from r2morph.core.binary import Binary
from r2morph.analysis.cfg import ControlFlowGraph, BasicBlock
from r2morph.analysis.symbolic.angr_bridge import AngrBridge
from r2morph.analysis.symbolic.state_manager import StateManager, StateSchedulingStrategy
from r2morph.analysis.symbolic.constraint_solver import ConstraintSolver, MBAExpression
from r2morph.analysis.symbolic.path_explorer import PathExplorer, ExplorationStrategy
from r2morph.analysis.symbolic.syntia_integration import SyntiaFramework


def _load_binary():
    binary_path = Path("dataset/elf_x86_64")
    bin_obj = Binary(binary_path)
    bin_obj.__enter__()
    bin_obj.analyze()
    return bin_obj


def test_angr_bridge_project_and_state():
    bin_obj = _load_binary()
    try:
        bridge = AngrBridge(bin_obj)
        assert bridge._should_exclude_simprocedure("malloc") is True
        assert bridge._should_exclude_simprocedure("custom_func") is False

        project = bridge.angr_project
        state = bridge.create_symbolic_state(project.entry, {"rax": 1})
        assert state is not None

        cfg = ControlFlowGraph(function_address=project.entry, function_name="entry")
        cfg.add_block(BasicBlock(address=project.entry, size=1))
        bridge.convert_r2_cfg_to_angr(cfg)
    finally:
        bin_obj.__exit__(None, None, None)


def test_state_manager_prune_and_merge():
    bin_obj = _load_binary()
    try:
        bridge = AngrBridge(bin_obj)
        project = bridge.angr_project
        state_a = project.factory.blank_state(addr=project.entry)
        state_b = project.factory.blank_state(addr=project.entry)
        state_c = project.factory.blank_state(addr=project.entry + 1)

        manager = StateManager(max_states=1, scheduling_strategy=StateSchedulingStrategy.PRIORITY_BASED)
        id_a = manager.add_state(state_a, priority=1.0)
        manager.add_state(state_b, priority=0.5)
        assert len(manager.active_states) <= 1

        manager.update_state_coverage(id_a, {0x1000, 0x2000})
        manager.update_state_priority(id_a, 2.0)
        assert manager.get_next_state() is not None

        merge_manager = StateManager(max_states=10)
        merge_manager.add_state(state_a, priority=1.0)
        merge_manager.add_state(state_b, priority=0.8)
        merge_manager.add_state(state_c, priority=0.7)

        merged = merge_manager.merge_equivalent_states()
        assert merged >= 1
    finally:
        bin_obj.__exit__(None, None, None)


def test_constraint_solver_path_and_mba():
    solver = ConstraintSolver(timeout=5)

    x = claripy.BVS("x", 8)
    constraints = [x == 1]
    result = solver.solve_path_constraints(constraints)
    assert result.satisfiable is True
    assert result.model is not None

    unsat = solver.solve_path_constraints([x == 1, x == 2])
    assert unsat.solver_used == "z3"

    mba = MBAExpression(expression="x", variables={"x"}, bit_width=8)
    mba_result = solver.simplify_mba_expression(mba)
    assert mba_result.satisfiable is True

    equiv = solver.check_semantic_equivalence("x", "x", {"x"})
    assert equiv.solver_used == "z3"

    stats = solver.get_solver_statistics()
    assert "queries_solved" in stats

    opaque = solver.detect_opaque_predicates([x == 1])
    assert isinstance(opaque, list)


def test_path_explorer_basic_run():
    bin_obj = _load_binary()
    try:
        bridge = AngrBridge(bin_obj)
        explorer = PathExplorer(bridge)
        result = explorer.explore_function(
            bridge.angr_project.entry,
            strategy=ExplorationStrategy.VM_HANDLER,
            max_paths=1,
            timeout=1,
        )
        assert result.execution_time >= 0.0

        handlers = explorer.find_vm_handlers(bridge.angr_project.entry, max_handlers=1)
        assert isinstance(handlers, list)
    finally:
        bin_obj.__exit__(None, None, None)


def test_syntia_framework_fallback_semantics():
    framework = SyntiaFramework()
    instructions = [
        {"bytes": "90", "disasm": "nop", "size": 1},
        {"bytes": b"\x90", "disasm": "nop", "size": 1},
    ]
    result = framework.synthesize_semantics(instructions, address=0x1000)
    assert result is not None
    assert len(result) == 2

    single = framework.learn_instruction_semantics(b"\x90", 0x2000, "nop", None)
    assert single is not None
