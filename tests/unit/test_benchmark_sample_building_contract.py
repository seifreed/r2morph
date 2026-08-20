"""Contract tests for benchmark sample construction helpers."""

from __future__ import annotations

from pathlib import Path

from r2morph.validation.benchmark_samples import (
    DEFAULT_TEST_SAMPLES,
    build_test_sample,
    build_test_samples,
)
from r2morph.validation.benchmark_types import TestSeverity
from tests.utils.assertions import expect


def test_build_test_sample_materializes_catalog_record(tmp_path) -> None:
    sample = build_test_sample(tmp_path, DEFAULT_TEST_SAMPLES[0])

    expect(sample.file_path == str(tmp_path / Path("vmprotect_sample.exe")))
    expect(sample.sample_hash == str(DEFAULT_TEST_SAMPLES[0]["sample_hash"]))
    expect(not (sample.severity is not TestSeverity.CRITICAL))
    expect(sample.source == "research_collection")


def test_build_test_samples_materializes_all_entries(tmp_path) -> None:
    samples = build_test_samples(tmp_path)

    expect(len(samples) == len(DEFAULT_TEST_SAMPLES))
    expect(samples[0].file_path.startswith(str(tmp_path)))
    expect(samples[-1].description == "Clean unobfuscated binary")
