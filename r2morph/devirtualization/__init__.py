"""
Devirtualization module for r2morph.

This module provides comprehensive devirtualization capabilities for
commercial packers like VMProtect and Themida, including:
- VM handler analysis and classification
- Mixed Boolean Arithmetic (MBA) simplification
- Control Flow Obfuscation (CFO) pattern removal
- Iterative simplification pipeline
- Binary rewriting and reconstruction
"""

from .binary_rewriter import BinaryRewriter
from .binary_rewriter_models import BinaryFormat, CodePatch, RelocationEntry, RewriteOperation, RewriteResult
from .cfo_simplifier import CFOSimplifier
from .cfo_simplifier_models import CFOPattern, CFOSimplificationResult, ControlFlowBlock, DispatcherInfo
from .iterative_simplifier import IterativeSimplifier
from .iterative_simplifier_models import SimplificationStrategy
from .iterative_simplifier_passes import CFOSimplificationPass, MBASimplificationPass, VMDevirtualizationPass
from .mba_solver import MBAExpression, MBASolver, SimplificationResult
from .vm_handler_analyzer import VMHandlerAnalyzer
from .vm_handler_models import VMArchitecture, VMHandler, VMHandlerType

__all__ = [
    "BinaryFormat",
    "BinaryRewriter",
    "CFOPattern",
    "CFOSimplificationPass",
    "CFOSimplificationResult",
    "CFOSimplifier",
    "CodePatch",
    "ControlFlowBlock",
    "DispatcherInfo",
    "IterativeSimplifier",
    "MBAExpression",
    "MBASimplificationPass",
    "MBASolver",
    "RelocationEntry",
    "RewriteOperation",
    "RewriteResult",
    "SimplificationResult",
    "SimplificationStrategy",
    "VMArchitecture",
    "VMDevirtualizationPass",
    "VMHandler",
    "VMHandlerAnalyzer",
    "VMHandlerType",
]
