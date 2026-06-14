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
from .iterative_simplifier_passes import CFOSimplificationPass, MBASimplificationPass, VMDevirtualizationPass
from .mba_solver import MBASolver
from .vm_handler_analyzer import VMHandlerAnalyzer
from .vm_handler_models import VMArchitecture, VMHandler, VMHandlerType

# Import types for better IDE support
try:
    from .iterative_simplifier import (
        SimplificationStrategy as SimplificationStrategy,
    )
    from .iterative_simplifier_passes import CFOSimplificationPass as CFOSimplificationPass
    from .iterative_simplifier_passes import MBASimplificationPass as MBASimplificationPass
    from .iterative_simplifier_passes import VMDevirtualizationPass as VMDevirtualizationPass
    from .mba_solver import MBAExpression as MBAExpression
    from .mba_solver import SimplificationResult as SimplificationResult
    from .vm_handler_models import VMArchitecture as VMArchitecture
    from .vm_handler_models import VMHandler as VMHandler
    from .vm_handler_models import VMHandlerType as VMHandlerType
except ImportError:
    # Graceful degradation if imports fail
    pass

__all__ = [
    "VMHandlerAnalyzer",
    "VMHandler",
    "MBASolver",
    "CFOSimplifier",
    "IterativeSimplifier",
    "BinaryRewriter",
    "VMHandlerType",
    "VMArchitecture",
    "MBAExpression",
    "SimplificationResult",
    "CFOPattern",
    "CFOSimplificationResult",
    "ControlFlowBlock",
    "DispatcherInfo",
    "SimplificationStrategy",
    "SimplificationResult",
    "BinaryFormat",
    "RewriteOperation",
    "RewriteResult",
    "CodePatch",
    "RelocationEntry",
    "CFOSimplificationPass",
    "MBASimplificationPass",
    "VMDevirtualizationPass",
]
