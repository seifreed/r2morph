from r2morph.validation.performance_regression_execution import (
    build_mutation_class_map,
    build_performance_metrics,
)


def test_build_mutation_class_map_contains_expected_passes() -> None:
    mutation_classes = build_mutation_class_map()

    assert {"nop", "substitute", "register"}.issubset(mutation_classes)


def test_build_performance_metrics_calculates_summary_stats() -> None:
    metrics = build_performance_metrics([1.0, 3.0, 5.0], {"peak_memory_mb": 8.0, "current_memory_mb": 4.0})

    assert metrics == {
        "execution_time_ms_mean": 3.0,
        "execution_time_ms_median": 3.0,
        "execution_time_ms_stdev": 2.0,
        "execution_time_ms_min": 1.0,
        "execution_time_ms_max": 5.0,
        "peak_memory_mb": 8.0,
        "current_memory_mb": 4.0,
    }
