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

# Symbolic execution and advanced analysis
from typing import Any as _Any

_AngrBridge: _Any = None
_ConstraintSolver: _Any = None
_PathExplorer: _Any = None
_StateManager: _Any = None
_SyntiaFramework: _Any = None
_SYNTIA_AVAILABLE: bool = False

try:
    from r2morph.analysis.symbolic import (
        AngrBridge as _AngrBridgeImport,
        ConstraintSolver as _ConstraintSolverImport,
        PathExplorer as _PathExplorerImport,
        StateManager as _StateManagerImport,
        SyntiaFramework as _SyntiaFrameworkImport,
        SYNTIA_AVAILABLE as _SYNTIA_AVAILABLE_IMPORT,
    )

    SYMBOLIC_AVAILABLE = True
    _AngrBridge = _AngrBridgeImport
    _ConstraintSolver = _ConstraintSolverImport
    _PathExplorer = _PathExplorerImport
    _StateManager = _StateManagerImport
    _SyntiaFramework = _SyntiaFrameworkImport
    _SYNTIA_AVAILABLE = _SYNTIA_AVAILABLE_IMPORT
except ImportError:
    SYMBOLIC_AVAILABLE = False

AngrBridge = _AngrBridge
ConstraintSolver = _ConstraintSolver
PathExplorer = _PathExplorer
StateManager = _StateManager
SyntiaFramework = _SyntiaFramework
SYNTIA_AVAILABLE = _SYNTIA_AVAILABLE

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
