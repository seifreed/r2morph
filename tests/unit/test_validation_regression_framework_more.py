from pathlib import Path

from r2morph.validation.regression import RegressionTestFramework, RegressionTestType


def test_regression_api_baseline_and_report(tmp_path: Path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    baseline = framework.create_api_compatibility_baseline("api_baseline_test")

    assert baseline.test_type == RegressionTestType.API_COMPATIBILITY
    assert "binary_import" in baseline.expected_output

    # Reload baselines to ensure persistence path
    framework2 = RegressionTestFramework(baseline_dir=str(tmp_path))
    assert "api_baseline_test" in framework2.baselines

    # Run regression test against the baseline
    result = framework2.run_regression_test("api_baseline_test")
    assert result.test_id == "api_baseline_test"

    report = framework2.generate_regression_report()
    assert "R2MORPH REGRESSION TEST REPORT" in report
