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

from .vm_handler_analyzer import VMHandlerAnalyzer
from .mba_solver import MBASolver
from .cfo_simplifier import CFOSimplifier
from .iterative_simplifier import IterativeSimplifier
from .binary_rewriter import BinaryRewriter

# Import types for better IDE support
try:
    from .vm_handler_analyzer import VMHandlerType as VMHandlerType, VMArchitecture as VMArchitecture
    from .mba_solver import MBAExpression as MBAExpression, SimplificationResult as SimplificationResult
    from .cfo_simplifier import (
        CFOPattern as CFOPattern,
        CFOSimplificationResult as CFOSimplificationResult,
        DispatcherInfo as DispatcherInfo,
    )
    from .iterative_simplifier import (
        SimplificationStrategy as SimplificationStrategy,
    )
    from .binary_rewriter import (
        BinaryFormat as BinaryFormat,
        RewriteOperation as RewriteOperation,
        RewriteResult as RewriteResult,
    )
except ImportError:
    # Graceful degradation if imports fail
    pass

__all__ = [
    "VMHandlerAnalyzer",
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
    "DispatcherInfo",
    "SimplificationStrategy",
    "SimplificationResult",
    "BinaryFormat",
    "RewriteOperation",
    "RewriteResult",
]
