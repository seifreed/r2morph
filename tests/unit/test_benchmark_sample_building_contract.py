"""Contract tests for benchmark sample construction helpers."""

from __future__ import annotations

from pathlib import Path

from r2morph.validation.benchmark_samples import (
    DEFAULT_TEST_SAMPLES,
    build_test_sample,
    build_test_samples,
)
from r2morph.validation.benchmark_types import TestSeverity


def test_build_test_sample_materializes_catalog_record(tmp_path) -> None:
    sample = build_test_sample(tmp_path, DEFAULT_TEST_SAMPLES[0])

    assert sample.file_path == str(tmp_path / Path("dataset/vmprotect_sample.exe"))
    assert sample.sample_hash == str(DEFAULT_TEST_SAMPLES[0]["sample_hash"])
    assert sample.severity is TestSeverity.CRITICAL
    assert sample.source == "research_collection"


def test_build_test_samples_materializes_all_entries(tmp_path) -> None:
    samples = build_test_samples(tmp_path)

    assert len(samples) == len(DEFAULT_TEST_SAMPLES)
    assert samples[0].file_path.startswith(str(tmp_path))
    assert samples[-1].description == "Clean unobfuscated binary"
