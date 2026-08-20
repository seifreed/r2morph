from r2morph.validation.benchmark_models import (
    AccuracyMetrics,
    BenchmarkCategory,
    BenchmarkResult,
    PerformanceMetrics,
    TestSample,
    TestSeverity,
)
from tests.utils.assertions import expect


def test_benchmark_models_round_trip() -> None:
    sample = TestSample(
        file_path="sample.bin",
        sample_hash="deadbeef",
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="sample",
        source="unit",
    )
    performance = PerformanceMetrics(1.0, 2.0, 3.0, 4.0, True)
    accuracy = AccuracyMetrics(1, 0, 1, 0, 1.0, 1.0, 1.0, 1.0)
    result = BenchmarkResult(sample, BenchmarkCategory.DETECTION, performance, accuracy, {}, "now", "dev")

    expect(sample.severity == TestSeverity.LOW)
    expect(BenchmarkCategory.BYPASS.value == "bypass")
    expect(not (performance.success is not True))
    expect(result.category == BenchmarkCategory.DETECTION)
