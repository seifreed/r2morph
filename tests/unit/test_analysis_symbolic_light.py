from __future__ import annotations

import pytest

from r2morph.analysis.symbolic import constraint_solver, path_explorer, state_manager


def test_symbolic_modules_handle_missing_dependencies() -> None:
    if not constraint_solver.ANGR_AVAILABLE:
        solver = constraint_solver.ConstraintSolver()
        result = solver.solve_path_constraints([])
        if constraint_solver.Z3_AVAILABLE:
            assert result.satisfiable is True
        else:
            assert result.satisfiable is False
    if not path_explorer.ANGR_AVAILABLE:
        with pytest.raises(ImportError):
            path_explorer.PathExplorer(None)
    if not state_manager.ANGR_AVAILABLE:
        manager = state_manager.StateManager()
        assert manager.add_state(object()) == -1
