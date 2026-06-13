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

from r2morph.validation.benchmark import ValidationFramework
from r2morph.validation.benchmark_types import (
    AccuracyMetrics,
    BenchmarkResult,
    PerformanceMetrics,
    TestSample,
)
from r2morph.validation.cfg_integrity import (
    CFGIntegrityChecker,
    CFGSnapshot,
    HardenedMutationValidator,
    IntegrityCheck,
    IntegrityReport,
    IntegrityStatus,
    IntegrityViolation,
)
from r2morph.validation.differ import (
    BinaryDiff,
    BinaryDiffer,
    ByteDiff,
    ChangeSeverity,
    DiffReport,
    DiffType,
    FunctionDiff,
    SectionDiff,
    compare_binaries,
)
from r2morph.validation.fuzzer import FuzzResult, MutationFuzzer
from r2morph.validation.integrity import BinaryIntegrityValidator, validate_binary_integrity
from r2morph.validation.leak_detection import (
    LeakDetectionResult,
    MemoryLeak,
    MemoryLeakDetector,
    MemorySnapshot,
    ObjectTracker,
    ResourceLeak,
    ResourceLeakDetector,
    ResourceLeakTestResult,
    create_memory_detector,
)
from r2morph.validation.manager import ValidationIssue, ValidationManager, ValidationOutcome
from r2morph.validation.mutation_fuzzer import (
    ContinuousFuzzer,
    FuzzCampaignResult,
    FuzzConfig,
    FuzzTestCase,
    MutationPassFuzzer,
    create_continuous_fuzzer,
    create_fuzzer,
)
from r2morph.validation.mutation_fuzzer import (
    FuzzResult as MutationFuzzResult,
)
from r2morph.validation.performance_regression import (
    BenchmarkConfig,
    PerformanceBenchmark,
    PerformanceMetric,
    PerformanceRegression,
    PerformanceRegressionSuite,
    PerformanceSnapshot,
    create_benchmark,
)
from r2morph.validation.regression import RegressionResult, RegressionTest, RegressionTester, RegressionTestFramework
from r2morph.validation.semantic import (
    MutationRegion,
    ObservableComparison,
    SemanticCheck,
    SemanticValidationReport,
    SemanticValidationResult,
    SemanticValidator,
    ValidationMode,
    ValidationResultStatus,
    validate_semantic_equivalence,
)
from r2morph.validation.semantic_invariants import (
    ControlFlowPreservationChecker,
    InvariantCategory,
    InvariantSeverity,
    InvariantSpec,
    InvariantViolation,
    RegisterPreservationChecker,
    SemanticInvariantChecker,
    SemanticInvariantRegistry,
    StackBalanceChecker,
)
from r2morph.validation.validator import (
    BinaryValidator,
    RuntimeComparisonConfig,
    ValidationResult,
    ValidationTestCase,
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
