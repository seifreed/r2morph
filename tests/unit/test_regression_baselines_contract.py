from __future__ import annotations

import r2morph
import r2morph.detection
from r2morph.validation import regression_baselines
from r2morph.validation.regression_models import RegressionTestType


def test_regression_baselines_api_compatibility_builds_real_baseline() -> None:
    baseline = regression_baselines.build_api_compatibility_baseline("api")

    assert baseline.test_id == "api"
    assert baseline.test_type is RegressionTestType.API_COMPATIBILITY
    assert "binary_import" in baseline.expected_output


def test_regression_baselines_detection_builds_with_fakes(monkeypatch) -> None:
    class FakeTech:
        def __init__(self, value: str) -> None:
            self.value = value

    class FakeResult:
        packer_detected = None
        vm_detected = True
        anti_analysis_detected = False
        control_flow_flattened = True
        mba_detected = False
        confidence_score = 0.75
        obfuscation_techniques = [FakeTech("b"), FakeTech("a")]

    class FakeDetector:
        def analyze_binary(self, _bin_obj):
            return FakeResult()

        def detect_custom_virtualizer(self, _bin_obj):
            return {"detected": True, "vm_type": "vm"}

        def detect_code_packing_layers(self, _bin_obj):
            return {"layers_detected": 2}

        def detect_metamorphic_engine(self, _bin_obj):
            return {"detected": False, "polymorphic_ratio": 0.25}

    class FakeBinary:
        def __init__(self, _path: str) -> None:
            self.name = "fake.bin"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def analyze(self) -> None:
            return None

    monkeypatch.setattr(r2morph, "Binary", FakeBinary)
    monkeypatch.setattr(r2morph.detection, "ObfuscationDetector", FakeDetector)

    baseline = regression_baselines.build_detection_baseline("det", "fake.bin", "hash")

    assert baseline.test_id == "det"
    assert baseline.test_type is RegressionTestType.DETECTION_ACCURACY
    assert baseline.input_hash == "hash"
    assert baseline.expected_output["obfuscation_techniques"][0].value == "a"
    assert baseline.expected_output["packing_layers"] == 2
