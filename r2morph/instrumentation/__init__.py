"""
Dynamic instrumentation module for r2morph.

This module provides runtime analysis capabilities using Frida for:
- Live binary instrumentation
- API call monitoring
- Anti-analysis detection and bypass
- Runtime unpacking assistance
- Memory dumping and analysis
"""

from r2morph.instrumentation.frida_engine import FRIDA_AVAILABLE, FridaEngine

__all__ = [
    "FRIDA_AVAILABLE",
    "FridaEngine",
]
