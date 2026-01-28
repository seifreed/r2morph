from pathlib import Path

from r2morph.validation.regression import RegressionTestFramework


def test_regression_framework_api_baseline(tmp_path: Path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    baseline = framework.create_api_compatibility_baseline("api_check")

    assert baseline.test_id == "api_check"
    assert "detector_instantiation" in baseline.expected_output

    result = framework.run_regression_test("api_check")
    assert result.test_id == "api_check"


def test_regression_framework_detection_baseline(tmp_path: Path):
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))

    binary_path = Path("dataset/elf_x86_64")
    baseline = framework.create_detection_baseline("det_check", str(binary_path))

    assert baseline.test_id == "det_check"
    assert "packer_detected" in baseline.expected_output

    result = framework.run_regression_test("det_check", str(binary_path))
    assert result.test_id == "det_check"
