from pathlib import Path

from r2morph.validation.regression import RegressionTestFramework, RegressionTestType
from tests.utils.assertions import expect


def test_regression_api_baseline_and_report(tmp_path: Path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    baseline = framework.create_api_compatibility_baseline("api_baseline_test")

    expect(baseline.test_type == RegressionTestType.API_COMPATIBILITY)
    expect(not ("binary_import" not in baseline.expected_output))

    # Reload baselines to ensure persistence path
    framework2 = RegressionTestFramework(baseline_dir=str(tmp_path))
    expect(not ("api_baseline_test" not in framework2.baselines))

    # Run regression test against the baseline
    result = framework2.run_regression_test("api_baseline_test")
    expect(result.test_id == "api_baseline_test")

    report = framework2.generate_regression_report()
    expect(not ("R2MORPH REGRESSION TEST REPORT" not in report))
