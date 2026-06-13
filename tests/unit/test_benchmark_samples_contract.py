"""Contract tests for benchmark sample catalog."""

from __future__ import annotations

from r2morph.validation.benchmark_samples import DEFAULT_TEST_SAMPLES
from r2morph.validation.benchmark_types import TestSeverity


def test_default_benchmark_samples_have_expected_shape() -> None:
    assert len(DEFAULT_TEST_SAMPLES) == 5

    required_keys = {
        "file_path",
        "sample_hash",
        "expected_packer",
        "expected_vm_protection",
        "expected_anti_analysis",
        "expected_cfo",
        "expected_mba",
        "severity",
        "description",
        "source",
    }

    for sample in DEFAULT_TEST_SAMPLES:
        assert required_keys.issubset(sample)
        assert isinstance(sample["severity"], TestSeverity)
        assert str(sample["file_path"]).startswith("dataset/")
