"""
Symbolic execution and analysis module for r2morph.

This module provides symbolic execution capabilities using angr,
constraint solving with Z3, and integration with the Syntia framework
for semantic learning during devirtualization.
"""

from importlib import import_module
from typing import Any as _Any

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "AngrBridge": ("r2morph.analysis.symbolic.angr_bridge", "AngrBridge"),
    "ConstraintSolver": ("r2morph.analysis.symbolic.constraint_solver", "ConstraintSolver"),
    "ConstraintType": ("r2morph.analysis.symbolic.constraint_solver_models", "ConstraintType"),
    "MBAExpression": ("r2morph.analysis.symbolic.constraint_solver_models", "MBAExpression"),
    "MAX_CONSTRAINT_AST_DEPTH": (
        "r2morph.analysis.symbolic.constraint_solver_parsing",
        "MAX_CONSTRAINT_AST_DEPTH",
    ),
    "PathExplorer": ("r2morph.analysis.symbolic.path_explorer", "PathExplorer"),
    "ResistanceMeasurement": ("r2morph.analysis.symbolic.resistance_probe", "ResistanceMeasurement"),
    "SolverResult": ("r2morph.analysis.symbolic.constraint_solver_models", "SolverResult"),
    "StateManager": ("r2morph.analysis.symbolic.state_manager", "StateManager"),
    "StateMetrics": ("r2morph.analysis.symbolic.state_manager_models", "StateMetrics"),
    "StateSchedulingStrategy": ("r2morph.analysis.symbolic.state_manager_models", "StateSchedulingStrategy"),
    "StructuralResistance": ("r2morph.analysis.symbolic.structural_resistance", "StructuralResistance"),
    "StructuralResistanceProbe": (
        "r2morph.analysis.symbolic.structural_resistance",
        "StructuralResistanceProbe",
    ),
    "SymbolicResistanceProbe": ("r2morph.analysis.symbolic.resistance_probe", "SymbolicResistanceProbe"),
}


def __getattr__(name: str) -> _Any:
    if name in {"SyntiaFramework", "SYNTIA_AVAILABLE"}:
        try:
            value = import_module("r2morph.analysis.symbolic.syntia_integration").SyntiaFramework
        except ImportError:
            value = None if name == "SyntiaFramework" else False
        else:
            if name == "SYNTIA_AVAILABLE":
                value = True
        globals()[name] = value
        return value
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _LAZY_EXPORTS[name]
    value = getattr(import_module(module_name), attr_name)
    globals()[name] = value
    return value


__all__ = [
    "MAX_CONSTRAINT_AST_DEPTH",
    "SYNTIA_AVAILABLE",
    "AngrBridge",
    "ConstraintSolver",
    "ConstraintType",
    "MBAExpression",
    "PathExplorer",
    "ResistanceMeasurement",
    "SolverResult",
    "StateManager",
    "StateMetrics",
    "StateSchedulingStrategy",
    "StructuralResistance",
    "StructuralResistanceProbe",
    "SymbolicResistanceProbe",
    "SyntiaFramework",
]


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
