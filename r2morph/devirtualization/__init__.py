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
from .iterative_simplifier import IterativeSimplifier
from .mba_solver import MBASolver
from .vm_handler_analyzer import VMHandlerAnalyzer

# Import types for better IDE support
try:
    from .cfo_simplifier import (
        CFOPattern as CFOPattern,
    )
    from .cfo_simplifier import (
        CFOSimplificationResult as CFOSimplificationResult,
    )
    from .cfo_simplifier import (
        DispatcherInfo as DispatcherInfo,
    )
    from .iterative_simplifier import (
        SimplificationStrategy as SimplificationStrategy,
    )
    from .mba_solver import MBAExpression as MBAExpression
    from .mba_solver import SimplificationResult as SimplificationResult
    from .vm_handler_analyzer import VMArchitecture as VMArchitecture
    from .vm_handler_analyzer import VMHandlerType as VMHandlerType
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
    "CodePatch",
    "RelocationEntry",
]
