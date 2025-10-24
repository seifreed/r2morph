"""
Dynamic instrumentation module for r2morph.

This module provides runtime analysis capabilities using Frida for:
- Live binary instrumentation
- API call monitoring
- Anti-analysis detection and bypass
- Runtime unpacking assistance
- Memory dumping and analysis
"""

from r2morph.instrumentation.frida_engine import FridaEngine
from r2morph.instrumentation.hooking_manager import HookingManager
from r2morph.instrumentation.runtime_analyzer import RuntimeAnalyzer
from r2morph.instrumentation.anti_analysis_detector import AntiAnalysisDetector

# Check Frida availability
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    frida = None

__all__ = [
    "FridaEngine",
    "HookingManager", 
    "RuntimeAnalyzer",
    "AntiAnalysisDetector",
    "FRIDA_AVAILABLE",
]