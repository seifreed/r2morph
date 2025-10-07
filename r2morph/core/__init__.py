"""
Core module for r2morph.

Contains the fundamental classes for binary analysis and transformation.
"""

from r2morph.core.binary import Binary
from r2morph.core.engine import MorphEngine
from r2morph.core.function import Function
from r2morph.core.instruction import Instruction

__all__ = ["Binary", "MorphEngine", "Function", "Instruction"]
