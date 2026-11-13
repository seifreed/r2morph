"""Mutation outcome normalization for adversarial benchmark reports."""

from __future__ import annotations

from scripts.adversarial_benchmark_constants import _PASS_STATUS_FIELDS
from scripts.protection_maturity_baseline import _APPLIED_COUNT_FIELDS, DEFAULT_MUTATION_NAME


def _capability_counts(records: object) -> dict[str, int]:
    if not isinstance(records, list):
        return {}
    counts: dict[str, int] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        capability = record.get("capability")
        if isinstance(capability, str) and capability:
            counts[capability] = counts.get(capability, 0) + 1
    return dict(sorted(counts.items()))


def _severity_counts(records: object) -> dict[str, int]:
    if not isinstance(records, list):
        return {}
    counts: dict[str, int] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        severity = record.get("severity")
        if isinstance(severity, str) and severity:
            counts[severity] = counts.get(severity, 0) + 1
    return dict(sorted(counts.items()))


def _diagnostic_reason(records: object) -> str | None:
    if not isinstance(records, list):
        return None
    for record in records:
        if not isinstance(record, dict):
            continue
        capability = record.get("capability", "unsupported capability")
        reason = record.get("reason", "pass precondition was not met")
        return f"{capability}: {reason}"
    return None


def _pass_result(stats: dict[str, object], pass_name: str = DEFAULT_MUTATION_NAME) -> dict[str, object]:
    virtualized = stats.get("functions_virtualized", 0)
    unsupported = stats.get("unsupported_functions_total", 0)
    partial = stats.get("partial_virtualization_total", 0)
    applied = next(
        (value for field in _APPLIED_COUNT_FIELDS if isinstance(value := stats.get(field), int) and value > 0),
        0,
    )
    if isinstance(applied, int) and applied > 0:
        status = "applied"
    elif (isinstance(unsupported, int) and unsupported > 0) or (isinstance(partial, int) and partial > 0):
        status = "omitted"
    else:
        status = "no-op"
    result: dict[str, object] = {
        "pass_name": pass_name,
        "status": status,
    }
    if pass_name == DEFAULT_MUTATION_NAME:
        result["functions_virtualized"] = virtualized
        result["unsupported_functions"] = unsupported
        result["partial_virtualization"] = partial
        reason = _diagnostic_reason(stats.get("unsupported_functions")) or _diagnostic_reason(
            stats.get("partial_virtualization")
        )
        if reason is not None:
            result["reason"] = reason
        unsupported_capabilities = _capability_counts(stats.get("unsupported_functions"))
        partial_capabilities = _capability_counts(stats.get("partial_virtualization"))
        unsupported_severities = _severity_counts(stats.get("unsupported_functions"))
        partial_severities = _severity_counts(stats.get("partial_virtualization"))
        if unsupported_capabilities:
            result["unsupported_capabilities"] = unsupported_capabilities
        if partial_capabilities:
            result["partial_virtualization_capabilities"] = partial_capabilities
        if unsupported_severities:
            result["unsupported_severities"] = unsupported_severities
        if partial_severities:
            result["partial_virtualization_severities"] = partial_severities
    else:
        result["mutations_applied"] = applied
    return result


def _merge_capability_summary(counters: dict[str, object], field: str, value: object) -> None:
    if not isinstance(value, dict):
        return
    aggregate = counters.get(field)
    if not isinstance(aggregate, dict):
        aggregate = {}
    for capability, count in value.items():
        if isinstance(capability, str) and isinstance(count, int):
            aggregate[capability] = aggregate.get(capability, 0) + count
    if aggregate:
        counters[field] = dict(sorted(aggregate.items()))


def _merge_pass_reason(counters: dict[str, object], field: str, row: dict[str, object]) -> None:
    reason = row.get("reason") or row.get("error_type") or "unspecified"
    reasons = counters.get(field)
    if not isinstance(reasons, dict):
        reasons = {}
    reasons[str(reason)] = reasons.get(str(reason), 0) + 1
    counters[field] = dict(sorted(reasons.items()))


def _pass_summary(samples: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    summary: dict[str, dict[str, object]] = {}
    for sample in samples:
        rows = sample.get("passes", [])
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            pass_name = row.get("pass_name")
            status = row.get("status")
            if not isinstance(pass_name, str) or not isinstance(status, str):
                continue
            counters = summary.setdefault(
                pass_name,
                {
                    "samples": 0,
                    "applied": 0,
                    "omitted": 0,
                    "no_op": 0,
                    "errors": 0,
                    "functions_virtualized": 0,
                    "unsupported_functions": 0,
                    "partial_virtualization": 0,
                },
            )
            counters["samples"] += 1
            status_field = _PASS_STATUS_FIELDS.get(status)
            if status_field is not None:
                counters[status_field] += 1
            if status == "omitted":
                _merge_pass_reason(counters, "omission_reasons", row)
            elif status == "error":
                _merge_pass_reason(counters, "error_reasons", row)
            for field in ("functions_virtualized", "unsupported_functions", "partial_virtualization"):
                value = row.get(field)
                if isinstance(value, int):
                    counters[field] += value
            if "mutations_applied" in row:
                counters.setdefault("mutations_applied", 0)
                value = row["mutations_applied"]
                if isinstance(value, int):
                    counters["mutations_applied"] += value
            _merge_capability_summary(counters, "unsupported_capabilities", row.get("unsupported_capabilities"))
            _merge_capability_summary(
                counters,
                "partial_virtualization_capabilities",
                row.get("partial_virtualization_capabilities"),
            )
            _merge_capability_summary(counters, "unsupported_severities", row.get("unsupported_severities"))
            _merge_capability_summary(
                counters,
                "partial_virtualization_severities",
                row.get("partial_virtualization_severities"),
            )
    return dict(sorted(summary.items()))
