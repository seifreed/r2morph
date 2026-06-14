"""Baseline construction helpers for regression validation."""

from __future__ import annotations

import importlib.util
import time
from typing import Any

from r2morph.validation.regression_models import BaselineResult, RegressionTestType


def compute_detection_output(binary_path: str) -> tuple[dict[str, Any], float]:
    """Run obfuscation detection on a binary and project it to a baseline-comparable dict.

    Returns the projected output dict and the wall-clock execution time. Shared by
    baseline construction and the live detection test so the two projections cannot drift.
    """
    from r2morph import Binary
    from r2morph.detection import ObfuscationDetector

    start_time = time.time()

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()

        detector = ObfuscationDetector()
        result = detector.analyze_binary(bin_obj)

        output = {
            "packer_detected": result.packer_detected.value if result.packer_detected else None,
            "vm_detected": result.vm_detected,
            "anti_analysis_detected": result.anti_analysis_detected,
            "control_flow_flattened": result.control_flow_flattened,
            "mba_detected": result.mba_detected,
            "confidence_score": round(result.confidence_score, 3),
            "techniques_count": len(result.obfuscation_techniques),
            "obfuscation_techniques": sorted(result.obfuscation_techniques[:20], key=lambda t: t.value),
        }

        custom_vm = detector.detect_custom_virtualizer(bin_obj)
        layers = detector.detect_code_packing_layers(bin_obj)
        metamorphic = detector.detect_metamorphic_engine(bin_obj)

        output.update(
            {
                "custom_vm_detected": custom_vm["detected"],
                "custom_vm_type": custom_vm.get("vm_type", ""),
                "packing_layers": layers["layers_detected"],
                "metamorphic_detected": metamorphic["detected"],
                "polymorphic_ratio": round(metamorphic.get("polymorphic_ratio", 0.0), 3),
            }
        )

    execution_time = time.time() - start_time
    return output, execution_time


def build_detection_baseline(test_id: str, binary_path: str, input_hash: str) -> BaselineResult:
    """Build a detection-accuracy baseline for a concrete binary."""
    expected_output, execution_time = compute_detection_output(binary_path)
    performance_baseline = {
        "execution_time": round(execution_time, 3),
        "max_allowed_time": round(execution_time * 2.0, 3),
    }

    return BaselineResult(
        test_id=test_id,
        test_type=RegressionTestType.DETECTION_ACCURACY,
        input_hash=input_hash,
        expected_output=expected_output,
        performance_baseline=performance_baseline,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        version="2.0.0-phase2",
    )


def compute_api_checks() -> dict[str, Any]:
    """Probe the public API surface and return availability flags.

    Shared by API-compatibility baseline construction and the live API test so the
    two projections cannot drift.
    """
    api_checks: dict[str, Any] = {}

    api_checks["binary_import"] = importlib.util.find_spec("r2morph") is not None
    api_checks["detection_import"] = importlib.util.find_spec("r2morph.detection") is not None
    api_checks["devirtualization_import"] = importlib.util.find_spec("r2morph.devirtualization") is not None

    try:
        from r2morph.detection import ObfuscationDetector

        detector = ObfuscationDetector()
        api_checks["detector_instantiation"] = True

        api_checks["analyze_binary_method"] = hasattr(detector, "analyze_binary")
        api_checks["detect_custom_virtualizer_method"] = hasattr(detector, "detect_custom_virtualizer")
        api_checks["get_comprehensive_report_method"] = hasattr(detector, "get_comprehensive_report")
    except Exception:
        api_checks["detector_instantiation"] = False
        api_checks["analyze_binary_method"] = False

    try:
        from r2morph.detection import PackerType

        api_checks["packer_type_enum"] = True
        api_checks["packer_type_count"] = len(list(PackerType))
    except ImportError:
        api_checks["packer_type_enum"] = False
        api_checks["packer_type_count"] = 0

    return api_checks


def build_api_compatibility_baseline(test_id: str) -> BaselineResult:
    """Build an API compatibility baseline."""
    return BaselineResult(
        test_id=test_id,
        test_type=RegressionTestType.API_COMPATIBILITY,
        input_hash="api_compatibility",
        expected_output=compute_api_checks(),
        performance_baseline={},
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        version="2.0.0-phase2",
    )
