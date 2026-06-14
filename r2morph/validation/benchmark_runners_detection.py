"""Detection benchmark runner."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from r2morph.validation.benchmark_types import (
    AccuracyMetrics,
    BenchmarkCategory,
    BenchmarkResult,
    PerformanceMetrics,
    TestSample,
)


def benchmark_detection(
    sample: TestSample,
    *,
    measure_performance: Callable[[Callable[[], dict[str, Any]]], tuple[PerformanceMetrics, Any]],
    calculate_accuracy_metrics: Callable[[dict[str, Any], dict[str, Any]], AccuracyMetrics],
) -> BenchmarkResult:
    from r2morph import Binary
    from r2morph.detection import ObfuscationDetector

    def run_detection() -> dict[str, Any]:
        with Binary(sample.file_path) as bin_obj:
            bin_obj.analyze()
            detector = ObfuscationDetector()
            result = detector.analyze_binary(bin_obj)

            return {
                "packer_detected": result.packer_detected.value if result.packer_detected else None,
                "vm_protection": result.vm_detected,
                "anti_analysis": result.anti_analysis_detected,
                "cfo_detected": result.control_flow_flattened,
                "mba_detected": result.mba_detected,
                "confidence_score": result.confidence_score,
                "techniques_count": len(result.obfuscation_techniques),
            }

    performance, analysis_result = measure_performance(run_detection)

    accuracy = None
    if performance.success and analysis_result:
        expected = {
            "packer_detected": sample.expected_packer,
            "vm_protection": sample.expected_vm_protection,
            "anti_analysis": sample.expected_anti_analysis,
            "cfo_detected": sample.expected_cfo,
            "mba_detected": sample.expected_mba,
        }
        accuracy = calculate_accuracy_metrics(expected, analysis_result)

    return BenchmarkResult(
        sample=sample,
        category=BenchmarkCategory.DETECTION,
        performance=performance,
        accuracy=accuracy,
        analysis_result=analysis_result or {},
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        r2morph_version="2.0.0-phase2",
    )
