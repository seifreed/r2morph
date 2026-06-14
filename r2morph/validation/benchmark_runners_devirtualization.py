"""Devirtualization benchmark runner."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from r2morph.validation.benchmark_types import BenchmarkCategory, BenchmarkResult, PerformanceMetrics, TestSample


def benchmark_devirtualization(
    sample: TestSample,
    *,
    measure_performance: Callable[[Callable[[], dict[str, Any]]], tuple[PerformanceMetrics, Any]],
) -> BenchmarkResult:
    from r2morph import Binary
    from r2morph.devirtualization import CFOSimplifier, IterativeSimplifier
    from r2morph.devirtualization.iterative_simplifier import SimplificationStrategy

    def run_devirtualization() -> dict[str, Any]:
        with Binary(sample.file_path) as bin_obj:
            bin_obj.analyze()

            cfo_simplifier = CFOSimplifier(bin_obj)
            functions = bin_obj.get_functions()[:3]

            cfo_results = []
            for func in functions:
                func_addr = func.get("offset", 0)
                result = cfo_simplifier.simplify_control_flow(func_addr)
                if result.success:
                    cfo_results.append(
                        {
                            "function": func_addr,
                            "complexity_reduction": result.original_complexity - result.simplified_complexity,
                            "patterns_detected": len(result.patterns_detected),
                        }
                    )

            iterative_simplifier = IterativeSimplifier(bin_obj)
            iter_result = iterative_simplifier.simplify(
                strategy=SimplificationStrategy.ADAPTIVE, max_iterations=3, timeout=30
            )

            return {
                "cfo_functions_simplified": len(cfo_results),
                "cfo_total_complexity_reduction": sum(r["complexity_reduction"] for r in cfo_results),
                "iterative_success": iter_result.success,
                "iterative_iterations": iter_result.metrics.iteration if iter_result.success else 0,
                "iterative_complexity_reduction": (
                    iter_result.metrics.complexity_reduction if iter_result.success else 0.0
                ),
            }

    performance, analysis_result = measure_performance(run_devirtualization)

    return BenchmarkResult(
        sample=sample,
        category=BenchmarkCategory.DEVIRTUALIZATION,
        performance=performance,
        accuracy=None,
        analysis_result=analysis_result or {},
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        r2morph_version="2.0.0-phase2",
    )
