"""Campaign level summaries and release signoff blocker calculations."""

from __future__ import annotations

from collections import Counter

from scripts.adversarial_benchmark_constants import _EXPECTED_TOOLS
from scripts.adversarial_benchmark_metrics import (
    _analyzer_effectiveness_by_pass,
    _coverage_percent,
    _decompiler_baseline_unavailable_by_pass,
)


def _campaign_summary(
    samples: list[dict[str, object]],
    fixture_count: int,
    pass_names: tuple[str, ...],
) -> dict[str, object]:
    expected_tools = (*_EXPECTED_TOOLS, "custom")
    observed_passes = {
        pass_name
        for sample in samples
        for row in sample.get("passes", [])
        if isinstance(row, dict) and isinstance(pass_name := row.get("pass_name"), str)
    }
    observed_tools = {
        tool
        for sample in samples
        for row in sample.get("tools", [])
        if isinstance(row, dict) and isinstance(tool := row.get("tool"), str)
    }
    observed_pass_runs_by_pass = Counter(
        pass_name
        for sample in samples
        for row in sample.get("passes", [])
        if isinstance(row, dict) and isinstance(pass_name := row.get("pass_name"), str)
    )
    observed_tool_runs_by_tool = Counter(
        tool
        for sample in samples
        for row in sample.get("tools", [])
        if isinstance(row, dict) and isinstance(tool := row.get("tool"), str)
    )
    observed_pass_runs = sum(1 for sample in samples for row in sample.get("passes", []) if isinstance(row, dict))
    observed_tool_runs = sum(1 for sample in samples for row in sample.get("tools", []) if isinstance(row, dict))
    applied_pass_runs = _pass_status_count(samples, "applied")
    omitted_pass_runs = _pass_status_count(samples, "omitted")
    error_pass_runs = _pass_status_count(samples, "error")
    completed_tools = sum(
        1
        for sample in samples
        for tool in sample["tools"]
        if isinstance(tool, dict) and tool.get("status") == "completed"
    )
    unavailable_tools = sum(
        1
        for sample in samples
        for tool in sample["tools"]
        if isinstance(tool, dict) and tool.get("status") == "unavailable"
    )
    error_tools = sum(
        1 for sample in samples for tool in sample["tools"] if isinstance(tool, dict) and tool.get("status") == "error"
    )
    completed_tool_names = _tools_with_status(samples, "completed")
    unavailable_tool_names = _tools_with_status(samples, "unavailable")
    error_tool_names = _tools_with_status(samples, "error")
    completed_tools_by_tool = _tool_status_counts(samples, "completed")
    unavailable_tools_by_tool = _tool_status_counts(samples, "unavailable")
    error_tools_by_tool = _tool_status_counts(samples, "error")
    expected_pass_runs = fixture_count * len(pass_names)
    expected_tool_runs = expected_pass_runs * len(expected_tools)
    missing_pass_runs_by_pass = {
        pass_name: missing_runs
        for pass_name in pass_names
        if (missing_runs := fixture_count - observed_pass_runs_by_pass[pass_name]) > 0
    }
    missing_tool_runs_by_tool = {
        tool: missing_runs
        for tool in expected_tools
        if (missing_runs := expected_pass_runs - observed_tool_runs_by_tool[tool]) > 0
    }
    non_completed_tool_runs_by_tool = {
        tool: runs
        for tool in expected_tools
        if (
            runs := missing_tool_runs_by_tool.get(tool, 0)
            + unavailable_tools_by_tool.get(tool, 0)
            + error_tools_by_tool.get(tool, 0)
        )
        > 0
    }
    non_completed_tool_runs = expected_tool_runs - completed_tools
    analyzer_effectiveness = _analyzer_effectiveness_by_pass(samples)
    summary: dict[str, object] = {
        "expected_pass_count": len(pass_names),
        "observed_pass_count": len(observed_passes),
        "missing_passes": sorted(set(pass_names) - observed_passes),
        "expected_pass_runs": expected_pass_runs,
        "observed_pass_runs": observed_pass_runs,
        "missing_pass_runs": expected_pass_runs - observed_pass_runs,
        "pass_run_coverage_percent": _coverage_percent(observed_pass_runs, expected_pass_runs),
        "applied_pass_runs": applied_pass_runs,
        "applied_pass_run_percent": _coverage_percent(applied_pass_runs, observed_pass_runs),
        "applied_pass_runs_by_pass": _pass_status_counts(samples, "applied"),
        "omitted_pass_runs": omitted_pass_runs,
        "omitted_pass_run_percent": _coverage_percent(omitted_pass_runs, observed_pass_runs),
        "omitted_pass_runs_by_pass": _pass_status_counts(samples, "omitted"),
        "omission_reasons_by_pass": _pass_reason_map(samples, "omitted"),
        "error_pass_runs": error_pass_runs,
        "error_pass_run_percent": _coverage_percent(error_pass_runs, observed_pass_runs),
        "error_pass_runs_by_pass": _pass_status_counts(samples, "error"),
        "error_reasons_by_pass": _pass_reason_map(samples, "error"),
        "missing_pass_runs_by_pass": missing_pass_runs_by_pass,
        "expected_tools": list(expected_tools),
        "observed_tools": sorted(observed_tools),
        "expected_tool_count": len(expected_tools),
        "observed_tool_count": len(observed_tools),
        "missing_tools": sorted(set(expected_tools) - observed_tools),
        "expected_tool_runs": expected_tool_runs,
        "observed_tool_runs": observed_tool_runs,
        "missing_tool_runs": expected_tool_runs - observed_tool_runs,
        "tool_run_coverage_percent": _coverage_percent(observed_tool_runs, expected_tool_runs),
        "missing_tool_runs_by_tool": missing_tool_runs_by_tool,
        "completed_tool_runs": completed_tools,
        "completed_tool_count": len(completed_tool_names),
        "completed_tools": completed_tool_names,
        "completed_tool_runs_by_tool": completed_tools_by_tool,
        "completed_tool_run_coverage_by_tool": _tool_run_coverage_by_tool(completed_tools_by_tool, expected_pass_runs),
        "completed_tool_run_percent": _coverage_percent(completed_tools, observed_tool_runs),
        "completed_tool_run_coverage_percent": _coverage_percent(completed_tools, expected_tool_runs),
        "incomplete_tool_coverage": _incomplete_tool_coverage(
            expected_tools,
            expected_pass_runs,
            {
                "completed": completed_tools_by_tool,
                "missing": missing_tool_runs_by_tool,
                "unavailable": unavailable_tools_by_tool,
                "error": error_tools_by_tool,
            },
        ),
        "non_completed_tool_runs": non_completed_tool_runs,
        "non_completed_tool_runs_by_tool": non_completed_tool_runs_by_tool,
        "tools_without_full_completion": sorted(non_completed_tool_runs_by_tool),
        "unavailable_tool_runs": unavailable_tools,
        "unavailable_tool_count": len(unavailable_tool_names),
        "unavailable_tools": unavailable_tool_names,
        "unavailable_tool_run_percent": _coverage_percent(unavailable_tools, observed_tool_runs),
        "unavailable_tool_runs_by_tool": unavailable_tools_by_tool,
        "unavailable_reasons_by_tool": _tool_reason_map(samples, "unavailable"),
        "error_tool_runs": error_tools,
        "error_tool_count": len(error_tool_names),
        "error_tools": error_tool_names,
        "error_tool_run_percent": _coverage_percent(error_tools, observed_tool_runs),
        "error_tool_runs_by_tool": error_tools_by_tool,
        "error_reasons_by_tool": _tool_reason_map(samples, "error"),
        "analyzer_effectiveness_by_pass": analyzer_effectiveness,
        "decompiler_baseline_unavailable_pairs_by_pass": _decompiler_baseline_unavailable_by_pass(
            analyzer_effectiveness
        ),
    }
    summary["adversarial_evidence_blockers"] = _adversarial_evidence_blockers(summary, pass_names)
    summary["adversarial_evidence_blocker_totals"] = _blocker_totals(
        summary["adversarial_evidence_blockers"],
        "total_adversarial_evidence_blockers",
    )
    return summary


def _adversarial_evidence_blockers(
    summary: dict[str, object],
    pass_names: tuple[str, ...],
) -> dict[str, object]:
    blockers: dict[str, object] = {}
    applied_by_pass = summary.get("applied_pass_runs_by_pass")
    if isinstance(applied_by_pass, dict):
        passes_without_applied_runs = sorted(
            pass_name for pass_name in pass_names if applied_by_pass.get(pass_name, 0) == 0
        )
        if passes_without_applied_runs:
            blockers["passes_without_applied_runs"] = passes_without_applied_runs
    for field in (
        "missing_passes",
        "missing_pass_runs_by_pass",
        "missing_tool_runs_by_tool",
        "error_pass_runs_by_pass",
        "incomplete_tool_coverage",
        "non_completed_tool_runs_by_tool",
        "tools_without_full_completion",
        "unavailable_tool_runs_by_tool",
        "unavailable_reasons_by_tool",
        "decompiler_baseline_unavailable_pairs_by_pass",
    ):
        value = summary.get(field)
        if isinstance(value, (list, dict)) and value:
            blockers[field] = value
    return blockers


def _release_signoff_blockers(tool_summary: dict[str, object]) -> dict[str, object]:
    unavailable = {
        tool: summary["unavailable_reasons"]
        for tool, summary in tool_summary.items()
        if isinstance(tool, str)
        and isinstance(summary, dict)
        and summary.get("unavailable", 0) > 0
        and isinstance(summary.get("unavailable_reasons"), dict)
    }
    return {"unavailable_analyzers": unavailable} if unavailable else {}


def _blocker_totals(blockers: dict[str, object], total_field: str) -> dict[str, int]:
    totals = {field: len(value) for field, value in blockers.items() if isinstance(value, (list, dict))}
    totals["blocker_categories"] = len(blockers)
    totals[total_field] = sum(count for field, count in totals.items() if field != "blocker_categories")
    return dict(sorted(totals.items()))


def _pass_status_count(samples: list[dict[str, object]], status: str) -> int:
    return sum(
        1
        for sample in samples
        for row in sample.get("passes", [])
        if isinstance(row, dict) and row.get("status") == status
    )


def _pass_status_counts(samples: list[dict[str, object]], status: str) -> dict[str, int]:
    counts = Counter(
        pass_name
        for sample in samples
        for row in sample.get("passes", [])
        if isinstance(row, dict) and row.get("status") == status and isinstance(pass_name := row.get("pass_name"), str)
    )
    return dict(sorted(counts.items()))


def _pass_reason_map(samples: list[dict[str, object]], status: str) -> dict[str, dict[str, int]]:
    reasons: dict[str, Counter[str]] = {}
    for sample in samples:
        for row in sample.get("passes", []):
            if not isinstance(row, dict) or row.get("status") != status:
                continue
            pass_name = row.get("pass_name")
            if not isinstance(pass_name, str):
                continue
            reason = str(row.get("reason") or row.get("error_type") or "unspecified")
            reasons.setdefault(pass_name, Counter())[reason] += 1
    return {pass_name: dict(sorted(counts.items())) for pass_name, counts in sorted(reasons.items())}


def _tool_status_counts(samples: list[dict[str, object]], status: str) -> dict[str, int]:
    counts = Counter(
        tool
        for sample in samples
        for row in sample.get("tools", [])
        if isinstance(row, dict) and row.get("status") == status and isinstance(tool := row.get("tool"), str)
    )
    return dict(sorted(counts.items()))


def _tools_with_status(samples: list[dict[str, object]], status: str) -> list[str]:
    return sorted(
        {
            tool
            for sample in samples
            for row in sample.get("tools", [])
            if isinstance(row, dict) and row.get("status") == status and isinstance(tool := row.get("tool"), str)
        }
    )


def _tool_run_coverage_by_tool(counts: dict[str, int], expected_runs: int) -> dict[str, float]:
    return {tool: _coverage_percent(count, expected_runs) for tool, count in sorted(counts.items())}


def _incomplete_tool_coverage(
    expected_tools: tuple[str, ...],
    expected_runs: int,
    counts_by_status: dict[str, dict[str, int]],
) -> list[dict[str, object]]:
    rows = []
    for tool in expected_tools:
        completed_runs = counts_by_status["completed"].get(tool, 0)
        if completed_runs == expected_runs:
            continue
        rows.append(
            {
                "tool": tool,
                "completed_runs": completed_runs,
                "missing_runs": counts_by_status["missing"].get(tool, 0),
                "unavailable_runs": counts_by_status["unavailable"].get(tool, 0),
                "error_runs": counts_by_status["error"].get(tool, 0),
                "completed_run_coverage_percent": _coverage_percent(completed_runs, expected_runs),
            }
        )
    return rows


def _tool_reason_map(samples: list[dict[str, object]], status: str) -> dict[str, dict[str, int]]:
    reasons: dict[str, Counter[str]] = {}
    for sample in samples:
        for row in sample.get("tools", []):
            if not isinstance(row, dict) or row.get("status") != status or not isinstance(tool := row.get("tool"), str):
                continue
            reason = str(row.get("reason") or row.get("error_type") or row.get("detail") or "unspecified")
            reasons.setdefault(tool, Counter())[reason] += 1
    return {tool: dict(sorted(counts.items())) for tool, counts in sorted(reasons.items())}
