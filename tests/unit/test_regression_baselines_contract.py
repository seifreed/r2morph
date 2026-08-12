from __future__ import annotations

from pathlib import Path

from r2morph.validation import regression_baselines
from r2morph.validation.regression_models import RegressionTestType


def test_regression_baselines_api_compatibility_builds_real_baseline() -> None:
    baseline = regression_baselines.build_api_compatibility_baseline("api")

    assert baseline.test_id == "api"
    assert baseline.test_type is RegressionTestType.API_COMPATIBILITY
    assert "binary_import" in baseline.expected_output


def test_regression_baselines_detection_builds_from_real_binary() -> None:
    binary_path = Path(__file__).parents[2] / "dataset" / "elf_x86_64"
    baseline = regression_baselines.build_detection_baseline("det", str(binary_path), "hash")

    assert (
        baseline.test_id == "det"
        and baseline.test_type is RegressionTestType.DETECTION_ACCURACY
        and baseline.input_hash == "hash"
        and {"confidence_score", "obfuscation_techniques", "packing_layers"} <= baseline.expected_output.keys()
    )
