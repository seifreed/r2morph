import hashlib
from pathlib import Path

from r2morph.validation.regression import RegressionTestFramework


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def test_regression_framework_mismatch_reporting(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    baseline_dir = tmp_path / "baselines"

    framework = RegressionTestFramework(baseline_dir=str(baseline_dir))
    baseline = framework.create_detection_baseline("det_mismatch", str(binary_path))

    # Force a mismatch to exercise comparison logic
    baseline.expected_output["vm_detected"] = not baseline.expected_output.get("vm_detected", False)
    framework.baselines[baseline.test_id] = baseline

    result = framework.run_regression_test("det_mismatch", str(binary_path))
    assert result.test_id == "det_mismatch"
    assert isinstance(result.issues, list)

    framework.test_results.append(result)
    report = framework.generate_regression_report()
    assert "REGRESSION TEST REPORT" in report
