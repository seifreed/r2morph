"""
Dynamic instrumentation module for r2morph.

This module provides runtime analysis capabilities using Frida for:
- Live binary instrumentation
- API call monitoring
- Anti-analysis detection and bypass
- Runtime unpacking assistance
- Memory dumping and analysis
"""

from typing import TYPE_CHECKING

from r2morph.instrumentation.frida_engine import FridaEngine

# Check Frida availability
if TYPE_CHECKING:
    import frida
else:
    try:
        import frida
    except ImportError:
        frida = None

FRIDA_AVAILABLE = frida is not None

__all__ = [
    "FridaEngine",
    "FRIDA_AVAILABLE",
]
