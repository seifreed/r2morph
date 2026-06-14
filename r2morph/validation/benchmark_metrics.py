"""Pure benchmark metric helpers."""

from __future__ import annotations

from typing import Any

from r2morph.validation.benchmark_metrics_measurement import measure_performance
from r2morph.validation.benchmark_types import AccuracyMetrics


def calculate_accuracy_metrics(expected: dict[str, Any], actual: dict[str, Any]) -> AccuracyMetrics:
    """Compute accuracy metrics from expected and actual benchmark results."""
    fields = ["packer_detected", "vm_protection", "anti_analysis", "cfo_detected", "mba_detected"]
    tp = fp = tn = fn = 0

    for field in fields:
        exp_val = expected.get(field, False)
        act_val = actual.get(field, False)
        if exp_val and act_val:
            tp += 1
        elif not exp_val and act_val:
            fp += 1
        elif not exp_val and not act_val:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    return AccuracyMetrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        accuracy=accuracy,
    )


__all__ = ["measure_performance", "calculate_accuracy_metrics"]
