"""Contract tests for benchmark reporting helpers."""

import csv
import hashlib
import json

from r2morph.validation.benchmark_reporting import (
    export_results,
    generate_report,
    generate_validation_summary,
)
from r2morph.validation.benchmark_types import (
    AccuracyMetrics,
    BenchmarkCategory,
    BenchmarkResult,
    PerformanceMetrics,
    TestSample,
    TestSeverity,
)


def _make_result(tmp_path):
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"abc")
    sample_hash = hashlib.sha256(sample_file.read_bytes()).hexdigest()
    sample = TestSample(
        file_path=str(sample_file),
        sample_hash=sample_hash,
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="benchmark",
        source="unit_test",
    )
    performance = PerformanceMetrics(
        execution_time=1.5,
        memory_usage_mb=2.0,
        cpu_usage_percent=3.0,
        peak_memory_mb=4.0,
        success=True,
        error_message=None,
    )
    accuracy = AccuracyMetrics(1, 0, 4, 0, 1.0, 1.0, 1.0, 1.0)
    return BenchmarkResult(sample, BenchmarkCategory.DETECTION, performance, accuracy, {"ok": True}, "now", "dev")


def test_validation_summary_and_report(tmp_path) -> None:
    result = _make_result(tmp_path)
    summary = generate_validation_summary([result])
    assert summary["total_tests"] == 1
    assert summary["categories"]["detection"]["total"] == 1

    report = generate_report([result])
    assert "R2MORPH VALIDATION REPORT" in report
    assert "SUCCESS RATE" in report.upper()


def test_export_results_json_and_csv(tmp_path) -> None:
    result = _make_result(tmp_path)
    json_path = tmp_path / "results.json"
    csv_path = tmp_path / "results.csv"

    export_results([result], str(json_path), "json")
    export_results([result], str(csv_path), "csv")

    with json_path.open() as f:
        data = json.load(f)
    assert data["summary"]["total_tests"] == 1

    with csv_path.open(newline="") as f:
        rows = list(csv.reader(f))
    assert rows[0][0] == "sample_path"
    assert rows[1][0].endswith("sample.bin")
