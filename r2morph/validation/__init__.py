"""
R2MORPH Validation Module

This module provides comprehensive testing and validation capabilities:
- Binary validation and similarity checking
- Fuzzing and robustness testing  
- Performance benchmarking and regression testing
- Real-world validation suite
"""

from r2morph.validation.fuzzer import MutationFuzzer, FuzzResult
from r2morph.validation.regression import RegressionTester, RegressionTest, RegressionResult, RegressionTestFramework
from r2morph.validation.validator import BinaryValidator, ValidationResult
from r2morph.validation.benchmark import ValidationFramework, BenchmarkResult, TestSample, PerformanceMetrics, AccuracyMetrics

__all__ = [
    # Core Validation
    "BinaryValidator",
    "ValidationResult",
    
    # Fuzzing
    "MutationFuzzer",
    "FuzzResult",
    
    # Regression Testing
    "RegressionTester",
    "RegressionTest", 
    "RegressionResult",
    "RegressionTestFramework",
    
    # Benchmarking & Performance
    "ValidationFramework",
    "BenchmarkResult", 
    "TestSample", 
    "PerformanceMetrics", 
    "AccuracyMetrics"
]
