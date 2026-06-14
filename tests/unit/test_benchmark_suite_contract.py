from __future__ import annotations

from types import SimpleNamespace

from r2morph.validation import benchmark_suite
from r2morph.validation.benchmark import ValidationFramework
from r2morph.validation.benchmark_types import BenchmarkCategory


class _FakeSample:
    file_exists = True
    file_path = "sample.bin"
    description = "sample"

    def verify_hash(self) -> bool:
        return True


def _fake_result(name: str) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        performance=SimpleNamespace(success=True, execution_time=1.0),
    )


def test_benchmark_suite_execution_helper_runs_all_categories() -> None:
    def detect(sample):
        return _fake_result(f"d:{sample.description}")

    def devirt(sample):
        return _fake_result(f"v:{sample.description}")

    def pipeline(sample):
        return _fake_result(f"p:{sample.description}")

    results, summary = benchmark_suite.run_validation_suite(
        [_FakeSample()],
        [BenchmarkCategory.DETECTION, BenchmarkCategory.DEVIRTUALIZATION, BenchmarkCategory.FULL_PIPELINE],
        detect,
        devirt,
        pipeline,
        lambda items: {"total_tests": len(items), "success_rate": 1.0, "avg_execution_time": 1.0},
        __import__("logging").getLogger("test"),
    )

    assert [result.name for result in results] == ["d:sample", "v:sample", "p:sample"]
    assert summary["total_tests"] == 3


def test_validation_framework_delegates_suite_execution(tmp_path) -> None:
    framework = ValidationFramework(test_data_dir=str(tmp_path))
    framework.test_samples = [_FakeSample()]
    framework._generate_validation_summary = lambda results: {  # type: ignore[method-assign]
        "total_tests": len(results),
        "success_rate": 1.0,
        "avg_execution_time": 1.0,
    }

    summary = framework.run_validation_suite([BenchmarkCategory.DETECTION])

    assert summary["total_tests"] == 1
    assert len(framework.benchmark_results) == 1
