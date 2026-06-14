"""Detection helpers for enhanced binary analysis."""

from __future__ import annotations

from typing import Any


def run_detection(binary: Any, results: Any) -> Any:
    """Run obfuscation detection on the binary and populate results."""
    from r2morph.detection import ObfuscationDetector

    detector = ObfuscationDetector()
    results.detection_result = detector.analyze_binary(binary)
    results.custom_vm = detector.detect_custom_virtualizer(binary)
    results.layers = detector.detect_code_packing_layers(binary)
    results.metamorphic = detector.detect_metamorphic_engine(binary)
    return detector, results.detection_result

