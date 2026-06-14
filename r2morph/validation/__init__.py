"""R2MORPH Validation Module."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_LAZY_EXPORTS = {
    "BinaryValidator": "r2morph.validation.validator",
    "RuntimeComparisonConfig": "r2morph.validation.validator",
    "ValidationResult": "r2morph.validation.validator",
    "ValidationTestCase": "r2morph.validation.validator",
    "ValidationManager": "r2morph.validation.manager",
    "ValidationOutcome": "r2morph.validation.manager",
    "ValidationIssue": "r2morph.validation.manager",
    "MutationFuzzer": "r2morph.validation.fuzzer",
    "FuzzResult": "r2morph.validation.fuzzer_models",
    "RegressionTestType": "r2morph.validation.regression_models",
    "BaselineResult": "r2morph.validation.regression_models",
    "RegressionTest": "r2morph.validation.regression_models",
    "RegressionResult": "r2morph.validation.regression_models",
    "NewRegressionResult": "r2morph.validation.regression_models",
    "FuzzConfig": "r2morph.validation.mutation_fuzzer",
    "FuzzTestCase": "r2morph.validation.mutation_fuzzer",
    "MutationFuzzResult": "r2morph.validation.mutation_fuzzer",
    "FuzzCampaignResult": "r2morph.validation.mutation_fuzzer",
    "MutationPassFuzzer": "r2morph.validation.mutation_fuzzer",
    "ContinuousFuzzer": "r2morph.validation.mutation_fuzzer",
    "create_fuzzer": "r2morph.validation.mutation_fuzzer",
    "create_continuous_fuzzer": "r2morph.validation.mutation_fuzzer",
    "RegressionTester": "r2morph.validation.regression_legacy",
    "RegressionTestFramework": "r2morph.validation.regression",
    "ValidationFramework": "r2morph.validation.benchmark",
    "BenchmarkCategory": "r2morph.validation.benchmark_models",
    "BenchmarkResult": "r2morph.validation.benchmark_models",
    "TestSample": "r2morph.validation.benchmark_models",
    "TestSeverity": "r2morph.validation.benchmark_models",
    "PerformanceMetrics": "r2morph.validation.benchmark_models",
    "AccuracyMetrics": "r2morph.validation.benchmark_models",
    "PerformanceBenchmark": "r2morph.validation.performance_regression",
    "PerformanceMetric": "r2morph.validation.performance_regression_models",
    "PerformanceSnapshot": "r2morph.validation.performance_regression_models",
    "PerformanceRegression": "r2morph.validation.performance_regression_models",
    "BenchmarkConfig": "r2morph.validation.performance_regression_models",
    "PerformanceRegressionSuite": "r2morph.validation.performance_regression_suite",
    "create_benchmark": "r2morph.validation.performance_regression",
    "MemorySnapshot": "r2morph.validation.leak_detection_models",
    "MemoryLeak": "r2morph.validation.leak_detection_models",
    "LeakDetectionResult": "r2morph.validation.leak_detection_models",
    "ObjectTracker": "r2morph.validation.object_tracker",
    "MemoryLeakDetector": "r2morph.validation.leak_detection",
    "ResourceLeak": "r2morph.validation.leak_detection_models",
    "ResourceLeakTestResult": "r2morph.validation.leak_detection_models",
    "ResourceLeakDetector": "r2morph.validation.resource_leak_detection",
    "create_memory_detector": "r2morph.validation.leak_detection",
    "BinaryIntegrityValidator": "r2morph.validation.integrity",
    "validate_binary_integrity": "r2morph.validation.integrity",
    "InvariantCategory": "r2morph.validation.semantic_invariant_models",
    "InvariantSeverity": "r2morph.validation.semantic_invariant_models",
    "InvariantSpec": "r2morph.validation.semantic_invariant_models",
    "InvariantViolation": "r2morph.validation.semantic_invariant_models",
    "SemanticInvariantRegistry": "r2morph.validation.semantic_invariant_models",
    "SemanticInvariantChecker": "r2morph.validation.semantic_invariants",
    "StackBalanceChecker": "r2morph.validation.semantic_invariants",
    "RegisterPreservationChecker": "r2morph.validation.semantic_invariants",
    "ControlFlowPreservationChecker": "r2morph.validation.semantic_invariants",
    "ValidationMode": "r2morph.validation.semantic",
    "ValidationResultStatus": "r2morph.validation.semantic",
    "MutationRegion": "r2morph.validation.semantic",
    "SemanticCheck": "r2morph.validation.semantic",
    "ObservableComparison": "r2morph.validation.semantic",
    "SemanticValidationResult": "r2morph.validation.semantic",
    "SemanticValidationReport": "r2morph.validation.semantic",
    "SemanticValidator": "r2morph.validation.semantic",
    "validate_semantic_equivalence": "r2morph.validation.semantic",
    "DiffType": "r2morph.validation.differ_models",
    "ChangeSeverity": "r2morph.validation.differ_models",
    "ByteDiff": "r2morph.validation.differ_models",
    "SectionDiff": "r2morph.validation.differ_models",
    "FunctionDiff": "r2morph.validation.differ_models",
    "BinaryDiff": "r2morph.validation.differ_models",
    "DiffReport": "r2morph.validation.differ_models",
    "BinaryDiffer": "r2morph.validation.differ",
    "compare_binaries": "r2morph.validation.differ",
    "IntegrityStatus": "r2morph.validation.cfg_integrity",
    "IntegrityViolation": "r2morph.validation.cfg_integrity",
    "IntegrityReport": "r2morph.validation.cfg_integrity",
    "IntegrityCheck": "r2morph.validation.cfg_integrity",
    "CFGSnapshot": "r2morph.validation.cfg_integrity",
    "CFGIntegrityChecker": "r2morph.validation.cfg_integrity",
    "HardenedMutationValidator": "r2morph.validation.cfg_integrity",
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    if name in _LAZY_EXPORTS:
        module = import_module(_LAZY_EXPORTS[name])
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
