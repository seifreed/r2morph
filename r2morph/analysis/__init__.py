"""
Analysis module for binary analysis utilities.
"""

# Symbolic execution and advanced analysis remain lazily loaded because the
# optional angr stack is heavy and should not be imported for unrelated core
# analysis workflows.

from __future__ import annotations

from importlib import import_module
from typing import Any as _Any

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    # ABI checking
    "ABIChecker": ("r2morph.analysis.abi_checker", "ABIChecker"),
    "ABISpec": ("r2morph.analysis.abi_checker", "ABISpec"),
    "ABIType": ("r2morph.analysis.abi_checker", "ABIType"),
    "ABIViolation": ("r2morph.analysis.abi_checker", "ABIViolation"),
    "ABIViolationType": ("r2morph.analysis.abi_checker", "ABIViolationType"),
    "ABI_SPECS": ("r2morph.analysis.abi_checker", "ABI_SPECS"),
    "detect_abi": ("r2morph.analysis.abi_checker", "detect_abi"),
    # Analysis orchestration
    "AnalysisOptions": ("r2morph.analysis.enhanced_analyzer", "AnalysisOptions"),
    "AnalysisResults": ("r2morph.analysis.enhanced_analyzer", "AnalysisResults"),
    "BinaryAnalyzer": ("r2morph.analysis.analyzer", "BinaryAnalyzer"),
    "BasicBlock": ("r2morph.analysis.cfg", "BasicBlock"),
    "CFGBuilder": ("r2morph.analysis.cfg", "CFGBuilder"),
    "CallEdge": ("r2morph.analysis.call_graph", "CallEdge"),
    "CallGraph": ("r2morph.analysis.call_graph", "CallGraph"),
    "CallGraphBuilder": ("r2morph.analysis.call_graph_builder", "CallGraphBuilder"),
    "CallNode": ("r2morph.analysis.call_graph", "CallNode"),
    "CallType": ("r2morph.analysis.call_graph", "CallType"),
    "ControlFlowGraph": ("r2morph.analysis.cfg", "ControlFlowGraph"),
    "AddressRange": ("r2morph.analysis.critical_nodes", "AddressRange"),
    "CriticalNode": ("r2morph.analysis.critical_nodes", "CriticalNode"),
    "CriticalNodeDetector": ("r2morph.analysis.critical_nodes", "CriticalNodeDetector"),
    "Criticality": ("r2morph.analysis.pattern_preservation", "Criticality"),
    "DataFlowAnalyzer": ("r2morph.analysis.dataflow", "DataFlowAnalyzer"),
    "DataFlowDirection": ("r2morph.analysis.dataflow", "DataFlowDirection"),
    "DataFlowResult": ("r2morph.analysis.dataflow", "DataFlowResult"),
    "DefUseAnalyzer": ("r2morph.analysis.defuse", "DefUseAnalyzer"),
    "DefUseChain": ("r2morph.analysis.dataflow", "DefUseChain"),
    "DefWeb": ("r2morph.analysis.defuse", "DefWeb"),
    "Dependency": ("r2morph.analysis.dependencies", "Dependency"),
    "DependencyAnalyzer": ("r2morph.analysis.dependencies", "DependencyAnalyzer"),
    "DependencyType": ("r2morph.analysis.dependencies", "DependencyType"),
    "DiffAnalyzer": ("r2morph.analysis.diff_analyzer", "DiffAnalyzer"),
    "DiffStats": ("r2morph.analysis.diff_analyzer", "DiffStats"),
    "EnhancedAnalysisOrchestrator": ("r2morph.analysis.enhanced_analyzer", "EnhancedAnalysisOrchestrator"),
    "ExceptionAction": ("r2morph.analysis.exception", "ExceptionAction"),
    "ExceptionAwareCFGBuilder": ("r2morph.analysis.exception", "ExceptionAwareCFGBuilder"),
    "ExceptionFrame": ("r2morph.analysis.exception", "ExceptionFrame"),
    "ExceptionInfoReader": ("r2morph.analysis.exception", "ExceptionInfoReader"),
    "ExceptionTableEntry": ("r2morph.analysis.exception", "ExceptionTableEntry"),
    "ExclusionZone": ("r2morph.analysis.pattern_preservation", "ExclusionZone"),
    "IndirectJump": ("r2morph.analysis.switch_table", "IndirectJump"),
    "InstructionLiveness": ("r2morph.analysis.liveness", "InstructionLiveness"),
    "Invariant": ("r2morph.analysis.invariants", "Invariant"),
    "InvariantDetector": ("r2morph.analysis.invariants", "InvariantDetector"),
    "InvariantType": ("r2morph.analysis.invariants", "InvariantType"),
    "InterferenceGraph": ("r2morph.analysis.liveness", "InterferenceGraph"),
    "JumpTable": ("r2morph.analysis.switch_table", "JumpTable"),
    "JumpTableEntry": ("r2morph.analysis.switch_table", "JumpTableEntry"),
    "JumpTableType": ("r2morph.analysis.switch_table", "JumpTableType"),
    "LandingPad": ("r2morph.analysis.exception", "LandingPad"),
    "LiveRange": ("r2morph.analysis.liveness", "LiveRange"),
    "LivenessAnalysis": ("r2morph.analysis.liveness", "LivenessAnalysis"),
    "MutationSafetyScorer": ("r2morph.analysis.critical_nodes", "MutationSafetyScorer"),
    "PatternPreservationManager": ("r2morph.analysis.pattern_preservation", "PatternPreservationManager"),
    "PatternType": ("r2morph.analysis.pattern_preservation", "PatternType"),
    "PointerAnalysis": ("r2morph.analysis.pointer_analysis", "PointerAnalysis"),
    "PreservedPattern": ("r2morph.analysis.pattern_preservation", "PreservedPattern"),
    "RecursionType": ("r2morph.analysis.call_graph", "RecursionType"),
    "Register": ("r2morph.analysis.dataflow", "Register"),
    "SemanticValidator": ("r2morph.analysis.invariants", "SemanticValidator"),
    "SwitchTableAnalyzer": ("r2morph.analysis.switch_table", "SwitchTableAnalyzer"),
    "TypeInference": ("r2morph.analysis.type_inference", "TypeInference"),
    "TypeCategory": ("r2morph.analysis.type_inference_types", "TypeCategory"),
    "TypeInfo": ("r2morph.analysis.type_inference_types", "TypeInfo"),
    "PrimitiveType": ("r2morph.analysis.type_inference_types", "PrimitiveType"),
    "StructField": ("r2morph.analysis.type_inference_types", "StructField"),
    "TypeInferenceResult": ("r2morph.analysis.type_inference_types", "TypeInferenceResult"),
    "Use": ("r2morph.analysis.dataflow", "Use"),
    "UseWeb": ("r2morph.analysis.defuse", "UseWeb"),
    "build_call_graph": ("r2morph.analysis.call_graph_builder", "build_call_graph"),
    "build_call_graph_cached": ("r2morph.analysis.call_graph_builder", "build_call_graph_cached"),
    "check_enhanced_dependencies": ("r2morph.analysis.enhanced_analyzer", "check_enhanced_dependencies"),
    "create_exclusion_zones": ("r2morph.analysis.critical_nodes", "create_exclusion_zones"),
    "get_safe_mutation_addresses": ("r2morph.analysis.critical_nodes", "get_safe_mutation_addresses"),
    "infer_type": ("r2morph.analysis.type_inference", "infer_type"),
    "propagate_types": ("r2morph.analysis.type_inference", "propagate_types"),
}

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
    if name in _SYMBOLIC_NAMES:
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

    if name in _LAZY_EXPORTS:
        module_name, attr_name = _LAZY_EXPORTS[name]
        value = getattr(import_module(module_name), attr_name)
        globals()[name] = value
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


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
    "EnhancedAnalysisOrchestrator",
    "AnalysisOptions",
    "AnalysisResults",
    "check_enhanced_dependencies",
    "ABIChecker",
    "ABISpec",
    "ABIType",
    "ABIViolation",
    "ABIViolationType",
    "detect_abi",
    "ABI_SPECS",
    "SwitchTableAnalyzer",
    "JumpTable",
    "JumpTableEntry",
    "JumpTableType",
    "IndirectJump",
    "ExceptionInfoReader",
    "ExceptionFrame",
    "ExceptionTableEntry",
    "ExceptionAction",
    "LandingPad",
    "ExceptionAwareCFGBuilder",
    "TypeCategory",
    "PrimitiveType",
    "TypeInfo",
    "StructField",
    "TypeInferenceResult",
    "TypeInference",
    "PointerAnalysis",
    "infer_type",
    "propagate_types",
    "DataFlowDirection",
    "Register",
    "Definition",
    "Use",
    "DefUseChain",
    "DataFlowResult",
    "DataFlowAnalyzer",
    "LiveRange",
    "InstructionLiveness",
    "InterferenceGraph",
    "LivenessAnalysis",
    "DefWeb",
    "UseWeb",
    "DefUseAnalyzer",
    "AddressRange",
    "CriticalNode",
    "CriticalNodeDetector",
    "MutationSafetyScorer",
    "create_exclusion_zones",
    "get_safe_mutation_addresses",
    "PatternPreservationManager",
    "PatternType",
    "PreservedPattern",
    "ExclusionZone",
    "Criticality",
    "AngrBridge",
    "ConstraintSolver",
    "PathExplorer",
    "StateManager",
    "SyntiaFramework",
    "SYMBOLIC_AVAILABLE",
    "SYNTIA_AVAILABLE",
]
