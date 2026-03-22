"""
R2MORPH Validation Module

This module provides comprehensive testing and validation capabilities:
- Binary validation and similarity checking
- Fuzzing and robustness testing
- Performance benchmarking and regression testing
- Real-world validation suite
- Binary integrity validation for post-mutation checks
- Semantic equivalence guarantees for mutations
- Memory leak detection
"""

from r2morph.validation.fuzzer import MutationFuzzer, FuzzResult
from r2morph.validation.integrity import BinaryIntegrityValidator, validate_binary_integrity
from r2morph.validation.manager import ValidationIssue, ValidationManager, ValidationOutcome
from r2morph.validation.regression import RegressionTester, RegressionTest, RegressionResult, RegressionTestFramework
from r2morph.validation.validator import (
    BinaryValidator,
    RuntimeComparisonConfig,
    ValidationResult,
    ValidationTestCase,
)
from r2morph.validation.benchmark import (
    ValidationFramework,
    BenchmarkResult,
    TestSample,
    PerformanceMetrics,
    AccuracyMetrics,
)
from r2morph.validation.semantic_invariants import (
    InvariantCategory,
    InvariantSeverity,
    InvariantSpec,
    InvariantViolation,
    SemanticInvariantRegistry,
    SemanticInvariantChecker,
    StackBalanceChecker,
    RegisterPreservationChecker,
    ControlFlowPreservationChecker,
)
from r2morph.validation.semantic import (
    ValidationMode,
    ValidationResultStatus,
    MutationRegion,
    SemanticCheck,
    ObservableComparison,
    SemanticValidationResult,
    SemanticValidationReport,
    SemanticValidator,
    validate_semantic_equivalence,
)
from r2morph.validation.differ import (
    DiffType,
    ChangeSeverity,
    ByteDiff,
    SectionDiff,
    FunctionDiff,
    BinaryDiff,
    DiffReport,
    BinaryDiffer,
    compare_binaries,
)
from r2morph.validation.cfg_integrity import (
    IntegrityStatus,
    IntegrityViolation,
    IntegrityReport,
    IntegrityCheck,
    CFGSnapshot,
    CFGIntegrityChecker,
    HardenedMutationValidator,
)
from r2morph.validation.mutation_fuzzer import (
    FuzzConfig,
    FuzzTestCase,
    FuzzResult as MutationFuzzResult,
    FuzzCampaignResult,
    MutationPassFuzzer,
    ContinuousFuzzer,
    create_fuzzer,
    create_continuous_fuzzer,
)
from r2morph.validation.performance_regression import (
    PerformanceMetric,
    PerformanceSnapshot,
    PerformanceRegression,
    BenchmarkConfig,
    PerformanceBenchmark,
    PerformanceRegressionSuite,
    create_benchmark,
)
from r2morph.validation.leak_detection import (
    MemorySnapshot,
    MemoryLeak,
    LeakDetectionResult,
    ObjectTracker,
    MemoryLeakDetector,
    ResourceLeak,
    ResourceLeakTestResult,
    ResourceLeakDetector,
    create_memory_detector,
)

__all__ = [
    # Core Validation
    "BinaryValidator",
    "RuntimeComparisonConfig",
    "ValidationResult",
    "ValidationTestCase",
    "ValidationManager",
    "ValidationOutcome",
    "ValidationIssue",
    # Fuzzing
    "MutationFuzzer",
    "FuzzResult",
    # Mutation Fuzzer
    "FuzzConfig",
    "FuzzTestCase",
    "MutationFuzzResult",
    "FuzzCampaignResult",
    "MutationPassFuzzer",
    "ContinuousFuzzer",
    "create_fuzzer",
    "create_continuous_fuzzer",
    # Regression Testing
    "RegressionTester",
    "RegressionTest",
    "RegressionResult",
    "RegressionTestFramework",
    # Performance
    "ValidationFramework",
    "BenchmarkResult",
    "TestSample",
    "PerformanceMetrics",
    "AccuracyMetrics",
    "PerformanceBenchmark",
    "PerformanceMetric",
    "PerformanceSnapshot",
    "PerformanceRegression",
    "BenchmarkConfig",
    "PerformanceRegressionSuite",
    "create_benchmark",
    # Memory Leak Detection
    "MemorySnapshot",
    "MemoryLeak",
    "LeakDetectionResult",
    "ObjectTracker",
    "MemoryLeakDetector",
    "ResourceLeak",
    "ResourceLeakTestResult",
    "ResourceLeakDetector",
    "create_memory_detector",
    # Binary Integrity
    "BinaryIntegrityValidator",
    "validate_binary_integrity",
    # Semantic Invariants
    "InvariantCategory",
    "InvariantSeverity",
    "InvariantSpec",
    "InvariantViolation",
    "SemanticInvariantRegistry",
    "SemanticInvariantChecker",
    "StackBalanceChecker",
    "RegisterPreservationChecker",
    "ControlFlowPreservationChecker",
    # Semantic Validation
    "ValidationMode",
    "ValidationResultStatus",
    "MutationRegion",
    "SemanticCheck",
    "ObservableComparison",
    "SemanticValidationResult",
    "SemanticValidationReport",
    "SemanticValidator",
    "validate_semantic_equivalence",
    # Binary Diffing
    "DiffType",
    "ChangeSeverity",
    "ByteDiff",
    "SectionDiff",
    "FunctionDiff",
    "BinaryDiff",
    "DiffReport",
    "BinaryDiffer",
    "compare_binaries",
    # CFG Integrity
    "IntegrityStatus",
    "IntegrityViolation",
    "IntegrityReport",
    "IntegrityCheck",
    "CFGSnapshot",
    "CFGIntegrityChecker",
    "HardenedMutationValidator",
]
