"""
r2morph - A metamorphic binary transformation engine based on r2pipe and radare2

This package provides a modular framework for analyzing and transforming binary executables
through semantic-preserving mutations.
"""

__version__ = "0.1.0"
__author__ = "r2morph contributors"
__license__ = "MIT"

from r2morph.core.binary import Binary
from r2morph.core.engine import MorphEngine
from r2morph.pipeline.pipeline import Pipeline

__all__ = [
    "Binary",
    "MorphEngine",
    "Pipeline",
    "__version__",
]
