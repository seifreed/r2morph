"""
Analysis module for binary analysis utilities.
"""

from r2morph.analysis.analyzer import BinaryAnalyzer
from r2morph.analysis.cfg import BasicBlock, CFGBuilder, ControlFlowGraph
from r2morph.analysis.dependencies import Dependency, DependencyAnalyzer, DependencyType
from r2morph.analysis.diff_analyzer import DiffAnalyzer, DiffStats
from r2morph.analysis.invariants import (
    Invariant,
    InvariantDetector,
    InvariantType,
    SemanticValidator,
)

# Symbolic execution and advanced analysis
try:
    from r2morph.analysis.symbolic import (
        AngrBridge,
        ConstraintSolver,
        PathExplorer,
        StateManager,
        SyntiaFramework,
        SYNTIA_AVAILABLE,
    )
    SYMBOLIC_AVAILABLE = True
except ImportError:
    SYMBOLIC_AVAILABLE = False
    AngrBridge = None
    ConstraintSolver = None
    PathExplorer = None
    StateManager = None
    SyntiaFramework = None
    SYNTIA_AVAILABLE = False

__all__ = [
    "BinaryAnalyzer",
    "CFGBuilder",
    "ControlFlowGraph",
    "BasicBlock",
    "DependencyAnalyzer",
    "Dependency",
    "DependencyType",
    "InvariantDetector",
    "SemanticValidator",
    "Invariant",
    "InvariantType",
    "DiffAnalyzer",
    "DiffStats",
    # Symbolic execution (if available)
    "AngrBridge",
    "ConstraintSolver", 
    "PathExplorer",
    "StateManager",
    "SyntiaFramework",
    "SYMBOLIC_AVAILABLE",
    "SYNTIA_AVAILABLE",
]
