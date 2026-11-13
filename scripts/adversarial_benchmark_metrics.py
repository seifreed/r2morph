"""Per-tool result summaries and analyzer effectiveness aggregation."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from scripts.adversarial_benchmark_constants import _EXPECTED_TOOLS, _FULL_COVERAGE_PERCENT
from scripts.adversarial_benchmark_tools import _measure_tool


def _tool_duration_seconds(row: dict[str, object]) -> float:
    duration = 0.0
    for side in ("original", "protected"):
        metrics = row.get(side)
        if isinstance(metrics, dict) and isinstance(value := metrics.get("duration_seconds"), int | float):
            duration += value
    return duration


def _tool_duration_pair_count(row: dict[str, object]) -> int:
    original = row.get("original")
    protected = row.get("protected")
    if not isinstance(original, dict) or not isinstance(protected, dict):
        return 0
    return int(
        isinstance(original.get("duration_seconds"), int | float)
        and isinstance(protected.get("duration_seconds"), int | float)
    )


def _tool_metric_deltas(row: dict[str, object]) -> dict[str, float]:
    original = row.get("original")
    protected = row.get("protected")
    if not isinstance(original, dict) or not isinstance(protected, dict):
        return {}
    deltas: dict[str, float] = {}
    for key, original_value in original.items():
        if key in {"duration_seconds", "return_code", "exit_code", "status"}:
            continue
        protected_value = protected.get(key)
        if type(original_value) in {int, float} and type(protected_value) in {int, float}:
            deltas[f"total_{key}_delta"] = protected_value - original_value
    return deltas


def _tool_metric_pair_counts(row: dict[str, object]) -> dict[str, int]:
    original = row.get("original")
    protected = row.get("protected")
    if not isinstance(original, dict) or not isinstance(protected, dict):
        return {}
    counts: dict[str, int] = {}
    for key, original_value in original.items():
        if key in {"duration_seconds", "return_code", "exit_code", "status"}:
            continue
        protected_value = protected.get(key)
        if type(original_value) in {int, float} and type(protected_value) in {int, float}:
            counts[f"metric_{key}_pairs"] = 1
    return counts


def _merge_tool_reason(counters: dict[str, object], field: str, row: dict[str, object]) -> None:
    reason = row.get("reason") or row.get("error_type") or row.get("detail") or "unspecified"
    reasons = counters.get(field)
    if not isinstance(reasons, dict):
        reasons = {}
    reasons[str(reason)] = reasons.get(str(reason), 0) + 1
    counters[field] = dict(sorted(reasons.items()))


def _tool_summary(samples: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    summary: dict[str, dict[str, object]] = {}
    for sample in samples:
        rows = sample.get("tools", [])
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            tool = row.get("tool")
            status = row.get("status")
            if not isinstance(tool, str) or not isinstance(status, str):
                continue
            counters = summary.setdefault(
                tool,
                {
                    "runs": 0,
                    "completed": 0,
                    "unavailable": 0,
                    "errors": 0,
                    "changed": 0,
                    "duration_pairs": 0,
                    "total_duration_seconds": 0.0,
                },
            )
            counters["runs"] += 1
            if status == "completed":
                counters["completed"] += 1
                counters["duration_pairs"] += _tool_duration_pair_count(row)
                counters["total_duration_seconds"] += _tool_duration_seconds(row)
                for key, delta in _tool_metric_deltas(row).items():
                    counters[key] = counters.get(key, 0) + delta
                for key, count in _tool_metric_pair_counts(row).items():
                    counters[key] = counters.get(key, 0) + count
                if row.get("changed") is True:
                    counters["changed"] += 1
            elif status == "unavailable":
                counters["unavailable"] += 1
                _merge_tool_reason(counters, "unavailable_reasons", row)
            else:
                counters["errors"] += 1
                _merge_tool_reason(counters, "error_reasons", row)
    return dict(sorted(summary.items()))


def _decompiler_observations(row: dict[str, object]) -> dict[str, int]:
    """Extract comparable pseudocode observations from an analyzer pair."""
    original = row.get("original")
    protected = row.get("protected")
    if not isinstance(original, dict) or not isinstance(protected, dict):
        return {}
    original_status = original.get("decompiler_status")
    protected_status = protected.get("decompiler_status")
    if not isinstance(original_status, str) or not isinstance(protected_status, str):
        return {}
    baseline_unavailable = original_status == "unavailable"
    observed = int(not baseline_unavailable)
    completed_pairs = int(original_status == "completed" and protected_status == "completed")
    result = {
        "observed_pairs": observed,
        "completed_pairs": completed_pairs,
        "missing_pairs": int(observed and not completed_pairs),
        "baseline_unavailable_pairs": int(baseline_unavailable),
    }
    applied = row.get("pass_status", "applied") == "applied"
    result["applied_observed_pairs"] = int(applied and observed)
    result["applied_completed_pairs"] = int(applied and observed and completed_pairs == 1)
    result["applied_baseline_unavailable_pairs"] = int(applied and baseline_unavailable)
    for field in ("decompiler_entrypoints", "decompiler_lines", "decompiler_bytes"):
        original_value = original.get(field)
        protected_value = protected.get(field)
        if not isinstance(original_value, int | float) or not isinstance(protected_value, int | float):
            continue
        result[f"original_{field}"] = int(original_value)
        result[f"protected_{field}"] = int(protected_value)
        result[f"delta_{field}"] = int(protected_value - original_value)
    return result


def _new_effectiveness_tool_summary() -> dict[str, Any]:
    return {
        "runs": 0,
        "completed": 0,
        "unavailable": 0,
        "errors": 0,
        "changed": 0,
        "metric_deltas": {},
        "metric_pair_counts": {},
    }


def _accumulate_effectiveness_tool(tool_summary: dict[str, Any], row: dict[str, object]) -> None:
    tool_summary["runs"] += 1
    status = row.get("status")
    if status == "completed":
        tool_summary["completed"] += 1
        tool_summary["changed"] += int(row.get("changed") is True)
        for key, value in _tool_metric_deltas(row).items():
            tool_summary["metric_deltas"][key] = tool_summary["metric_deltas"].get(key, 0) + value
        for key, value in _tool_metric_pair_counts(row).items():
            tool_summary["metric_pair_counts"][key] = tool_summary["metric_pair_counts"].get(key, 0) + value
    elif status == "unavailable":
        tool_summary["unavailable"] += 1
    else:
        tool_summary["errors"] += 1
    observations = _decompiler_observations(row)
    if observations:
        decompiler = tool_summary.setdefault("decompiler", {})
        for key, value in observations.items():
            decompiler[key] = decompiler.get(key, 0) + value


def _finalize_effectiveness_tool_summary(tool_summary: dict[str, Any]) -> None:
    tool_summary["completion_percent"] = _coverage_percent(tool_summary["completed"], tool_summary["runs"])
    decompiler = tool_summary.get("decompiler")
    if isinstance(decompiler, dict):
        decompiler["completion_percent"] = _coverage_percent(
            decompiler["completed_pairs"],
            decompiler["observed_pairs"],
        )
        decompiler["applied_completion_percent"] = _coverage_percent(
            decompiler.get("applied_completed_pairs", 0),
            decompiler.get("applied_observed_pairs", 0),
        )


def _decompiler_baseline_unavailable_by_pass(
    effectiveness: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> dict[str, dict[str, int]]:
    gaps: dict[str, dict[str, int]] = {}
    for pass_name, tools in effectiveness.items():
        pass_gaps = {
            tool: int(decompiler["applied_baseline_unavailable_pairs"])
            for tool, summary in tools.items()
            if isinstance(summary, Mapping)
            and isinstance(decompiler := summary.get("decompiler"), Mapping)
            and isinstance(decompiler.get("applied_baseline_unavailable_pairs"), int)
            and decompiler["applied_baseline_unavailable_pairs"] > 0
        }
        if pass_gaps:
            gaps[pass_name] = dict(sorted(pass_gaps.items()))
    return dict(sorted(gaps.items()))


def _decompiler_evidence_complete(decompiler: Mapping[str, Any], sample_count: int, applied_pairs: int) -> bool:
    """Require complete coverage for pairs affected by the pass."""
    if applied_pairs == 0:
        return (
            decompiler.get("applied_observed_pairs") == 0
            and decompiler.get("applied_completed_pairs") == 0
            and decompiler.get("applied_baseline_unavailable_pairs", 0) == 0
            and decompiler.get("applied_completion_percent") == 0.0
        )
    applied_observed_pairs = decompiler.get("applied_observed_pairs", 0)
    applied_baseline_unavailable_pairs = decompiler.get("applied_baseline_unavailable_pairs", 0)
    return (
        0 <= applied_pairs <= sample_count
        and 0 < applied_observed_pairs <= applied_pairs
        and applied_observed_pairs + applied_baseline_unavailable_pairs == applied_pairs
        and decompiler.get("observed_pairs", 0) >= applied_observed_pairs
        and decompiler.get("completed_pairs", 0) >= applied_observed_pairs
        and decompiler.get("applied_completed_pairs") == applied_observed_pairs
        and decompiler.get("applied_completion_percent") == _FULL_COVERAGE_PERCENT
    )


def _analyzer_effectiveness_by_pass(samples: list[dict[str, object]]) -> dict[str, dict[str, dict[str, Any]]]:
    """Aggregate analyzer and decompiler evidence without hiding unavailable slots."""
    summary: dict[str, dict[str, dict[str, Any]]] = {}
    for sample in samples:
        rows = sample.get("tools", [])
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            pass_name = row.get("pass_name")
            tool = row.get("tool")
            if not isinstance(pass_name, str) or not isinstance(tool, str):
                continue
            pass_summary = summary.setdefault(pass_name, {})
            tool_summary = pass_summary.setdefault(tool, _new_effectiveness_tool_summary())
            _accumulate_effectiveness_tool(tool_summary, row)
    for pass_summary in summary.values():
        for tool_summary in pass_summary.values():
            _finalize_effectiveness_tool_summary(tool_summary)
    return {name: dict(sorted(values.items())) for name, values in sorted(summary.items())}


def _coverage_percent(observed: int, expected: int) -> float:
    if expected == 0:
        return 0.0
    return round(observed / expected * 100.0, 2)


def _passes_without_applications(report: dict[str, object]) -> tuple[str, ...]:
    """Return selected passes that did not transform a corpus fixture."""
    summary = report.get("pass_summary")
    if not isinstance(summary, dict):
        return ()
    return tuple(
        sorted(
            name
            for name, values in summary.items()
            if isinstance(name, str) and isinstance(values, dict) and values.get("applied") == 0
        )
    )


def _missing_tool_slot_error(report: dict[str, object]) -> str | None:
    summary = report.get("summary")
    if not isinstance(summary, dict):
        return "analyzer tool slot validation requires a corpus benchmark report"
    missing_runs = summary.get("missing_tool_runs")
    missing_tools = summary.get("missing_tools")
    if isinstance(missing_runs, int) and missing_runs == 0 and missing_tools == []:
        return None
    if isinstance(missing_tools, list) and missing_tools:
        return "missing analyzer tool slots: " + ", ".join(str(tool) for tool in missing_tools)
    return "missing analyzer tool runs"


def _measure_pair_tools(
    original: Path,
    protected: Path,
    original_metrics: dict[str, dict[str, object]] | None = None,
    measurement_cache: dict[tuple[str, str], dict[str, object]] | None = None,
    protected_digest: str | None = None,
) -> list[dict[str, object]]:
    cache = original_metrics if original_metrics is not None else {}
    rows = []
    for tool in (*_EXPECTED_TOOLS, "custom"):
        cache_key = (tool, protected_digest) if protected_digest is not None else None
        cached_row = measurement_cache.get(cache_key) if measurement_cache is not None and cache_key else None
        row = dict(cached_row) if cached_row is not None else _measure_tool(tool, original, protected, cache.get(tool))
        if measurement_cache is not None and cache_key is not None and cached_row is None:
            measurement_cache[cache_key] = dict(row)
        metric = row.get("original")
        if row.get("status") == "completed" and isinstance(metric, dict):
            cache[tool] = metric
        rows.append(row)
    return rows


def _measure_pair_tools(
    original: Path,
    protected: Path,
    original_metrics: dict[str, dict[str, object]] | None = None,
    measurement_cache: dict[tuple[str, str], dict[str, object]] | None = None,
    protected_digest: str | None = None,
) -> list[dict[str, object]]:
    cache = original_metrics if original_metrics is not None else {}
    rows = []
    for tool in (*_EXPECTED_TOOLS, "custom"):
        cache_key = (tool, protected_digest) if protected_digest is not None else None
        cached_row = measurement_cache.get(cache_key) if measurement_cache is not None and cache_key else None
        row = dict(cached_row) if cached_row is not None else _measure_tool(tool, original, protected, cache.get(tool))
        if measurement_cache is not None and cache_key is not None and cached_row is None:
            measurement_cache[cache_key] = dict(row)
        metric = row.get("original")
        if row.get("status") == "completed" and isinstance(metric, dict):
            cache[tool] = metric
        rows.append(row)
    return rows
