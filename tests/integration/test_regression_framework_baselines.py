from pathlib import Path

from r2morph.validation.regression import RegressionTestFramework
from tests.utils.assertions import expect


def test_regression_framework_api_baseline(tmp_path: Path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    baseline = framework.create_api_compatibility_baseline("api_check")

    expect(baseline.test_id == "api_check")
    expect(not ("detector_instantiation" not in baseline.expected_output))

    result = framework.run_regression_test("api_check")
    expect(result.test_id == "api_check")


def test_regression_framework_detection_baseline(tmp_path: Path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))

    binary_path = Path("fixtures/dataset/elf_x86_64")
    baseline = framework.create_detection_baseline("det_check", str(binary_path))

    expect(baseline.test_id == "det_check")
    expect(not ("packer_detected" not in baseline.expected_output))

    result = framework.run_regression_test("det_check", str(binary_path))
    expect(result.test_id == "det_check")
