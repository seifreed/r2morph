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
    from .vm_handler_analyzer import VMHandlerType, VMArchitecture
    from .mba_solver import MBAExpression, MBASimplificationResult  
    from .cfo_simplifier import CFOPattern, CFOSimplificationResult, DispatcherInfo
    from .iterative_simplifier import SimplificationStrategy, SimplificationResult
    from .binary_rewriter import BinaryFormat, RewriteOperation, RewriteResult
except ImportError:
    # Graceful degradation if imports fail
    pass

__all__ = [
    "VMHandlerAnalyzer",
    "MBASolver", 
    "CFOSimplifier",
    "IterativeSimplifier",
    "BinaryRewriter",
]