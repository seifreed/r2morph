from __future__ import annotations

from pathlib import Path

from r2morph.validation import PerformanceRegressionSuite as PublicPerformanceRegressionSuite
from r2morph.validation.performance_regression_suite import (
    PerformanceRegressionSuite as SuitePerformanceRegressionSuite,
)
from tests.utils.assertions import expect


def test_performance_regression_suite_is_reexported_from_validation_package() -> None:
    expect(not (PublicPerformanceRegressionSuite is not SuitePerformanceRegressionSuite))


def test_performance_regression_suite_records_added_tests() -> None:
    suite = SuitePerformanceRegressionSuite()
    suite.add_test(Path("sample.bin"), ["nop"], "baseline")

    expect(suite.test_binaries == [(Path("sample.bin"), ["nop"], "baseline")])
