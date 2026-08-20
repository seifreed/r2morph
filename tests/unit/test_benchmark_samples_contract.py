"""Contract tests for benchmark sample catalog."""

from __future__ import annotations

from pathlib import Path

from r2morph.validation.benchmark_samples import DEFAULT_TEST_SAMPLES
from r2morph.validation.benchmark_types import TestSeverity
from tests.utils.assertions import expect

_EXPECTED_LEN_DEFAULT_TEST_SAMPLES_5 = 5


def test_default_benchmark_samples_have_expected_shape() -> None:
    expect(len(DEFAULT_TEST_SAMPLES) == _EXPECTED_LEN_DEFAULT_TEST_SAMPLES_5)

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
        expect(required_keys.issubset(sample))
        expect(isinstance(sample["severity"], TestSeverity))
        expect(Path(sample["file_path"]).parent == Path("."))
