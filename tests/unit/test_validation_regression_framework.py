import pytest

from r2morph.validation.regression import RegressionTestFramework, RegressionTestType
from tests.utils.assertions import expect


def test_api_baseline_roundtrip_and_regression_run(tmp_path):
    baseline_dir = tmp_path / "baselines"
    framework = RegressionTestFramework(baseline_dir=str(baseline_dir))

    baseline = framework.create_api_compatibility_baseline("api_baseline")
    baseline_file = baseline_dir / "api_baseline.json"
    expect(baseline_file.exists())
    expect(baseline.test_id == "api_baseline")
    expect(baseline.test_type.value == "api_compatibility")

    reloaded = RegressionTestFramework(baseline_dir=str(baseline_dir))
    expect(not ("api_baseline" not in reloaded.baselines))

    result = reloaded.run_regression_test("api_baseline")
    expect(not (result.passed is not True))
    expect(result.issues == [])


def test_compare_outputs_and_performance_edges(tmp_path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))

    expected = {"score": 0.5, "techniques": ["a", "b"], "flag": True}
    actual = {"score": 0.55, "techniques": ["b", "a"], "flag": True}
    issues = framework._compare_outputs(expected, actual, RegressionTestType.API_COMPATIBILITY)
    expect(issues == [])

    actual_bad = {"score": 0.9, "techniques": ["a"], "flag": False}
    issues_bad = framework._compare_outputs(expected, actual_bad, RegressionTestType.API_COMPATIBILITY)
    expect(issues_bad)

    perf_issues = framework._compare_performance(
        {"execution_time_max": 0.01},
        {"execution_time": 0.5},
    )
    expect(perf_issues)


def test_generate_regression_report_empty_and_populated(tmp_path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    expect(framework.generate_regression_report() == "No regression test results available.")

    framework.create_api_compatibility_baseline("api_report")
    framework.run_regression_test("api_report")

    report = framework.generate_regression_report()
    expect(not ("R2MORPH REGRESSION TEST REPORT" not in report))
    expect(not ("api_report" not in report))


def test_run_regression_missing_baseline_raises(tmp_path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    with pytest.raises(ValueError):
        framework.run_regression_test("does_not_exist")
