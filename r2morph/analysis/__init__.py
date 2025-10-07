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
]
