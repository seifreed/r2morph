from pathlib import Path

import pytest

from r2morph.validation.regression import RegressionTestFramework, RegressionTestType


def test_api_baseline_roundtrip_and_regression_run(tmp_path):
    baseline_dir = tmp_path / "baselines"
    framework = RegressionTestFramework(baseline_dir=str(baseline_dir))

    baseline = framework.create_api_compatibility_baseline("api_baseline")
    baseline_file = baseline_dir / "api_baseline.json"
    assert baseline_file.exists()
    assert baseline.test_id == "api_baseline"
    assert baseline.test_type.value == "api_compatibility"

    reloaded = RegressionTestFramework(baseline_dir=str(baseline_dir))
    assert "api_baseline" in reloaded.baselines

    result = reloaded.run_regression_test("api_baseline")
    assert result.passed is True
    assert result.issues == []


def test_compare_outputs_and_performance_edges(tmp_path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))

    expected = {"score": 0.5, "techniques": ["a", "b"], "flag": True}
    actual = {"score": 0.55, "techniques": ["b", "a"], "flag": True}
    issues = framework._compare_outputs(expected, actual, RegressionTestType.API_COMPATIBILITY)
    assert issues == []

    actual_bad = {"score": 0.9, "techniques": ["a"], "flag": False}
    issues_bad = framework._compare_outputs(expected, actual_bad, RegressionTestType.API_COMPATIBILITY)
    assert issues_bad

    perf_issues = framework._compare_performance(
        {"execution_time_max": 0.01},
        {"execution_time": 0.5},
    )
    assert perf_issues


def test_generate_regression_report_empty_and_populated(tmp_path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    assert framework.generate_regression_report() == "No regression test results available."

    baseline = framework.create_api_compatibility_baseline("api_report")
    result = framework.run_regression_test("api_report")

    report = framework.generate_regression_report()
    assert "R2MORPH REGRESSION TEST REPORT" in report
    assert "api_report" in report


def test_run_regression_missing_baseline_raises(tmp_path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    with pytest.raises(ValueError):
        framework.run_regression_test("does_not_exist")
