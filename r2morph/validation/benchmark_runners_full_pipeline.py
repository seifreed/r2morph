"""Full-pipeline benchmark runner."""

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


def benchmark_full_pipeline(
    sample: TestSample,
    *,
    measure_performance: Callable[[Callable[[], dict[str, Any]]], tuple[PerformanceMetrics, Any]],
    calculate_accuracy_metrics: Callable[[dict[str, Any], dict[str, Any]], AccuracyMetrics],
) -> BenchmarkResult:
    from r2morph import Binary
    from r2morph.detection import AntiAnalysisBypass, ObfuscationDetector
    from r2morph.devirtualization import CFOSimplifier, IterativeSimplifier
    from r2morph.devirtualization.iterative_simplifier import SimplificationStrategy

    def run_full_pipeline() -> dict[str, Any]:
        with Binary(sample.file_path) as bin_obj:
            bin_obj.analyze()

            detector = ObfuscationDetector()
            detection_result = detector.analyze_binary(bin_obj)

            bypass_framework = AntiAnalysisBypass()
            detected_techniques = bypass_framework.detect_anti_analysis_techniques(bin_obj)
            bypass_applied = len(detected_techniques) > 0

            devirt_performed = False
            complexity_reduction = 0.0

            if detection_result.vm_detected or detection_result.control_flow_flattened:
                cfo_simplifier = CFOSimplifier(bin_obj)
                functions = bin_obj.get_functions()[:2]

                for func in functions:
                    func_addr = func.get("offset", 0)
                    result = cfo_simplifier.simplify_control_flow(func_addr)
                    if result.success:
                        complexity_reduction += result.original_complexity - result.simplified_complexity

                iterative_simplifier = IterativeSimplifier(bin_obj)
                iter_result = iterative_simplifier.simplify(
                    strategy=SimplificationStrategy.CONSERVATIVE, max_iterations=2, timeout=20
                )

                if iter_result.success:
                    complexity_reduction += iter_result.metrics.complexity_reduction
                    devirt_performed = True

            return {
                "detection_confidence": detection_result.confidence_score,
                "packer_detected": detection_result.packer_detected.value if detection_result.packer_detected else None,
                "vm_detected": detection_result.vm_detected,
                "anti_analysis_bypass_applied": bypass_applied,
                "devirtualization_performed": devirt_performed,
                "total_complexity_reduction": complexity_reduction,
                "obfuscation_techniques_count": len(detection_result.obfuscation_techniques),
                "pipeline_completed": True,
            }

    performance, analysis_result = measure_performance(run_full_pipeline)

    accuracy = None
    if performance.success and analysis_result:
        expected = {
            "packer_detected": sample.expected_packer,
            "vm_protection": sample.expected_vm_protection,
            "anti_analysis": sample.expected_anti_analysis,
            "cfo_detected": sample.expected_cfo,
            "mba_detected": sample.expected_mba,
        }

        actual = {
            "packer_detected": analysis_result.get("packer_detected"),
            "vm_protection": analysis_result.get("vm_detected", False),
            "anti_analysis": analysis_result.get("anti_analysis_bypass_applied", False),
            "cfo_detected": analysis_result.get("devirtualization_performed", False),
            "mba_detected": False,
        }

        accuracy = calculate_accuracy_metrics(expected, actual)

    return BenchmarkResult(
        sample=sample,
        category=BenchmarkCategory.FULL_PIPELINE,
        performance=performance,
        accuracy=accuracy,
        analysis_result=analysis_result or {},
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        r2morph_version="2.0.0-phase2",
    )
