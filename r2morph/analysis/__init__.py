"""
Analysis module for binary analysis utilities.
"""

from r2morph.analysis.abi_checker import (
    ABIChecker,
    ABISpec,
    ABIType,
    ABIViolation,
    ABIViolationType,
    detect_abi,
    ABI_SPECS,
)
from r2morph.analysis.analyzer import BinaryAnalyzer
from r2morph.analysis.cfg import BasicBlock, CFGBuilder, ControlFlowGraph
from r2morph.analysis.call_graph import (
    CallGraph,
    CallGraphBuilder,
    CallNode,
    CallEdge,
    CallType,
    RecursionType,
    build_call_graph,
    build_call_graph_cached,
)
from r2morph.analysis.dependencies import Dependency, DependencyAnalyzer, DependencyType
from r2morph.analysis.diff_analyzer import DiffAnalyzer, DiffStats
from r2morph.analysis.enhanced_analyzer import (
    AnalysisOptions,
    AnalysisResults,
    EnhancedAnalysisOrchestrator,
    check_enhanced_dependencies,
)
from r2morph.analysis.invariants import (
    Invariant,
    InvariantDetector,
    InvariantType,
    SemanticValidator,
)
from r2morph.analysis.switch_table import (
    IndirectJump,
    JumpTable,
    JumpTableEntry,
    JumpTableType,
    SwitchTableAnalyzer,
)
from r2morph.analysis.exception import (
    ExceptionAction,
    ExceptionFrame,
    ExceptionInfoReader,
    ExceptionTableEntry,
    ExceptionAwareCFGBuilder,
    LandingPad,
)
from r2morph.analysis.type_inference import (
    TypeCategory,
    PrimitiveType,
    TypeInfo,
    StructField,
    TypeInferenceResult,
    TypeInference,
    PointerAnalysis,
    infer_type,
    propagate_types,
)
from r2morph.analysis.dataflow import (
    DataFlowDirection,
    Register,
    Definition,
    Use,
    DefUseChain,
    DataFlowResult,
    DataFlowAnalyzer,
)
from r2morph.analysis.liveness import (
    LiveRange,
    InstructionLiveness,
    InterferenceGraph,
    LivenessAnalysis,
)
from r2morph.analysis.defuse import (
    DefWeb,
    UseWeb,
    DefUseAnalyzer,
)
from r2morph.analysis.critical_nodes import (
    AddressRange,
    CriticalNode,
    CriticalNodeDetector,
    MutationSafetyScorer,
    create_exclusion_zones,
    get_safe_mutation_addresses,
)
from r2morph.analysis.pattern_preservation import (
    PatternPreservationManager,
    PatternType,
    PreservedPattern,
    ExclusionZone,
    Criticality,
)

# Symbolic execution and advanced analysis.
#
# The symbolic subpackage pulls in angr, a heavy optional C-extension
# dependency. Importing it eagerly here forced every consumer of
# `r2morph.analysis` to load angr -- including the core import chain
# (mutations.abi_hook -> analysis.abi_checker), which merely needs ABI
# helpers. That eager import both violated adapter isolation (CLAUDE.md
# section 7: heavy externals must stay isolated) and broke the entire
# test suite at collection: angr imports `cle`, which emits a
# third-party DeprecationWarning that `pytest -W error` turns fatal.
#
# Resolved with PEP 562 lazy attribute loading: angr is imported only
# when a symbolic name is actually accessed, and the resolved values are
# cached into module globals so subsequent lookups skip __getattr__.
from typing import Any as _Any

_SYMBOLIC_NAMES = frozenset(
    {
        "AngrBridge",
        "ConstraintSolver",
        "PathExplorer",
        "StateManager",
        "SyntiaFramework",
        "SYNTIA_AVAILABLE",
        "SYMBOLIC_AVAILABLE",
    }
)


def __getattr__(name: str) -> _Any:
    if name not in _SYMBOLIC_NAMES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    try:
        from r2morph.analysis import symbolic as _symbolic
    except ImportError:
        resolved: dict[str, _Any] = {
            "AngrBridge": None,
            "ConstraintSolver": None,
            "PathExplorer": None,
            "StateManager": None,
            "SyntiaFramework": None,
            "SYNTIA_AVAILABLE": False,
            "SYMBOLIC_AVAILABLE": False,
        }
    else:
        resolved = {
            "AngrBridge": _symbolic.AngrBridge,
            "ConstraintSolver": _symbolic.ConstraintSolver,
            "PathExplorer": _symbolic.PathExplorer,
            "StateManager": _symbolic.StateManager,
            "SyntiaFramework": _symbolic.SyntiaFramework,
            "SYNTIA_AVAILABLE": _symbolic.SYNTIA_AVAILABLE,
            "SYMBOLIC_AVAILABLE": True,
        }

    globals().update(resolved)
    return resolved[name]


def __dir__() -> list[str]:
    return sorted(__all__)


__all__ = [
    "BinaryAnalyzer",
    "CFGBuilder",
    "ControlFlowGraph",
    "BasicBlock",
    "CallGraph",
    "CallGraphBuilder",
    "CallNode",
    "CallEdge",
    "CallType",
    "RecursionType",
    "build_call_graph",
    "build_call_graph_cached",
    "DependencyAnalyzer",
    "Dependency",
    "DependencyType",
    "InvariantDetector",
    "SemanticValidator",
    "Invariant",
    "InvariantType",
    "DiffAnalyzer",
    "DiffStats",
    # Enhanced analysis orchestrator
    "EnhancedAnalysisOrchestrator",
    "AnalysisOptions",
    "AnalysisResults",
    "check_enhanced_dependencies",
    # ABI checking
    "ABIChecker",
    "ABISpec",
    "ABIType",
    "ABIViolation",
    "ABIViolationType",
    "detect_abi",
    "ABI_SPECS",
    # Switch table analysis
    "SwitchTableAnalyzer",
    "JumpTable",
    "JumpTableEntry",
    "JumpTableType",
    "IndirectJump",
    # Exception handling
    "ExceptionInfoReader",
    "ExceptionFrame",
    "ExceptionTableEntry",
    "ExceptionAction",
    "LandingPad",
    "ExceptionAwareCFGBuilder",
    # Type inference
    "TypeCategory",
    "PrimitiveType",
    "TypeInfo",
    "StructField",
    "TypeInferenceResult",
    "TypeInference",
    "PointerAnalysis",
    "infer_type",
    "propagate_types",
    # Data flow analysis
    "DataFlowDirection",
    "Register",
    "Definition",
    "Use",
    "DefUseChain",
    "DataFlowResult",
    "DataFlowAnalyzer",
    # Liveness analysis
    "LiveRange",
    "InstructionLiveness",
    "InterferenceGraph",
    "LivenessAnalysis",
    # Def-use analysis
    "DefWeb",
    "UseWeb",
    "DefUseAnalyzer",
    # Critical node detection
    "AddressRange",
    "CriticalNode",
    "CriticalNodeDetector",
    "MutationSafetyScorer",
    "create_exclusion_zones",
    "get_safe_mutation_addresses",
    # Pattern preservation
    "PatternPreservationManager",
    "PatternType",
    "PreservedPattern",
    "ExclusionZone",
    "Criticality",
    # Symbolic execution (if available)
    "AngrBridge",
    "ConstraintSolver",
    "PathExplorer",
    "StateManager",
    "SyntiaFramework",
    "SYMBOLIC_AVAILABLE",
    "SYNTIA_AVAILABLE",
]
