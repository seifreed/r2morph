"""
Symbolic execution and analysis module for r2morph.

This module provides symbolic execution capabilities using angr,
constraint solving with Z3, and integration with the Syntia framework
for semantic learning during devirtualization.
"""

from r2morph.analysis.symbolic.angr_bridge import AngrBridge
from r2morph.analysis.symbolic.constraint_solver import ConstraintSolver
from r2morph.analysis.symbolic.path_explorer import PathExplorer
from r2morph.analysis.symbolic.state_manager import StateManager

# Syntia integration will be added in subsequent implementations
from typing import Any as _Any

_SyntiaFramework: _Any = None
try:
    from r2morph.analysis.symbolic.syntia_integration import SyntiaFramework as _SyntiaImport

    SYNTIA_AVAILABLE = True
    _SyntiaFramework = _SyntiaImport
except ImportError:
    SYNTIA_AVAILABLE = False

SyntiaFramework = _SyntiaFramework

__all__ = [
    "AngrBridge",
    "ConstraintSolver",
    "PathExplorer",
    "StateManager",
    "SyntiaFramework",
    "SYNTIA_AVAILABLE",
]
