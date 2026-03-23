"""Pure data helper functions for report generation.

Predicates, utilities, and data transformations with no CLI/rendering dependencies.

Report helpers: small helper/predicate functions for reporting.
Extracted from cli.py -- no logic changes.
"""

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from r2morph.core.engine import (
    _build_gate_failure_priority,
    _build_gate_failure_severity_priority,
    _summarize_gate_failures,
)

console = Console()

SEVERITY_ORDER = {
    "mismatch": 0,
    "without-coverage": 1,
    "bounded-only": 2,
    "clean": 3,
    "not-requested": 4,
}


def _first_available(*sources: Any) -> Any:
    """Return the first truthy value from sources, or the last one."""
    for source in sources:
        if source:
            return source
    return sources[-1] if sources else None


def _summary_first(
    summary: dict[str, Any],
    key: str,
    fallback: Any,
) -> Any:
    """Return a persisted summary value when present, otherwise the fallback."""
    value = summary.get(key)
    if value is None:
        return fallback
    if isinstance(value, (list, dict)) and not value:
        return fallback
    return value


def _visible_rows(
    rows: list[dict[str, Any]],
    visible_passes: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter row-shaped report data by visible pass names."""
    if not visible_passes:
        return [dict(row) for row in rows if row.get("pass_name")]
    return [dict(row) for row in rows if row.get("pass_name") and str(row.get("pass_name")) in visible_passes]


def _normalized_pass_map(
    normalized_pass_results: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index normalized per-pass rows by pass name."""
    return {str(row.get("pass_name")): dict(row) for row in normalized_pass_results if row.get("pass_name")}


def _is_risky_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass has issues worth prioritizing in triage views."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if int(evidence_summary.get("symbolic_binary_mismatched_regions", 0)) > 0:
        return True
    if int(evidence_summary.get("structural_issue_count", 0)) > 0:
        return True
    if str(symbolic_summary.get("severity", "not-requested")) in {
        "mismatch",
        "without-coverage",
        "bounded-only",
    }:
        return True
    return int(symbolic_summary.get("issue_count", 0)) > 0


def _is_covered_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass is clean and has effective symbolic coverage."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if not _is_clean_pass(evidence_summary, symbolic_summary):
        return False
    if int(symbolic_summary.get("symbolic_requested", 0)) <= 0:
        return False
    if int(symbolic_summary.get("without_coverage", 0)) > 0:
        return False
    return int(evidence_summary.get("symbolic_binary_regions_checked", 0)) > 0


def _is_uncovered_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass is clean but lacks effective symbolic coverage."""
    return _is_clean_pass(evidence_summary, symbolic_summary) and not _is_covered_pass(
        evidence_summary, symbolic_summary
    )


def _is_clean_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass is clean enough for positive triage views."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if int(evidence_summary.get("structural_issue_count", 0)) > 0:
        return False
    if int(evidence_summary.get("symbolic_binary_mismatched_regions", 0)) > 0:
        return False
    severity = str(symbolic_summary.get("severity", "not-requested"))
    if severity not in {"clean", "not-requested"}:
        return False
    return int(symbolic_summary.get("issue_count", 0)) == 0


def _has_symbolic_risk(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass has symbolic evidence worth triaging."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if int(evidence_summary.get("symbolic_binary_mismatched_regions", 0)) > 0:
        return True
    if str(symbolic_summary.get("severity", "not-requested")) in {
        "mismatch",
        "without-coverage",
        "bounded-only",
    }:
        return True
    return int(symbolic_summary.get("issue_count", 0)) > 0


def _has_structural_risk(evidence_summary: dict[str, Any] | None) -> bool:
    """Return True when a pass has structural evidence worth triaging."""
    evidence_summary = evidence_summary or {}
    return int(evidence_summary.get("structural_issue_count", 0)) > 0


def _gate_failure_result_count(gate_failures: dict[str, Any]) -> int:
    """Return a non-zero count when any persisted gate failure is present."""
    count = int(gate_failures.get("require_pass_severity_failure_count", 0) or 0)
    if gate_failures.get("min_severity_failed"):
        count += 1
    if gate_failures.get("all_passed") is False and count == 0:
        count = 1
    return count


def _severity_threshold_met(
    severity_rows: list[dict[str, object]],
    min_severity_rank: int | None,
) -> bool:
    """Return True when at least one severity row meets the requested threshold."""
    if min_severity_rank is None:
        return True
    if not severity_rows:
        return False
    return any(
        SEVERITY_ORDER.get(str(row.get("severity", "not-requested")), 99) <= min_severity_rank for row in severity_rows
    )


def _pass_severity_requirements_met(
    severity_rows: list[dict[str, object]],
    requirements: list[tuple[str, str, int]],
) -> tuple[bool, list[str]]:
    """Check whether all required passes meet their minimum allowed severity rank."""
    if not requirements:
        return True, []
    by_pass = {str(row.get("pass_name", "")): row for row in severity_rows}
    failures: list[str] = []
    for pass_name, severity, rank in requirements:
        row = by_pass.get(pass_name)
        if row is None:
            failures.append(f"{pass_name}=missing(expected <= {severity})")
            continue
        actual = str(row.get("severity", "not-requested"))
        actual_rank = SEVERITY_ORDER.get(actual, 99)
        if actual_rank > rank:
            failures.append(f"{pass_name}={actual}(expected <= {severity})")
    return not failures, failures


def _report_view_has_results(
    *,
    mutation_count: int,
    only_failed_gates: bool,
    failed_gates: bool,
    gate_failure_count: int | None = None,
    only_risky_passes: bool = False,
    risky_pass_count: int | None = None,
    pass_count: int | None = None,
) -> bool:
    """Determine whether a filtered report view should count as non-empty."""
    if only_failed_gates:
        if gate_failure_count is not None:
            return gate_failure_count > 0
        return failed_gates
    if only_risky_passes and risky_pass_count is not None:
        return risky_pass_count > 0
    if pass_count is not None:
        return pass_count > 0
    return mutation_count > 0


def _select_report_mutations(
    *,
    all_mutations: list[dict[str, Any]],
    degraded_validation: bool,
    failed_gates: bool,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_filters: bool,
    selected_risk_pass_names: set[str],
    resolved_only_pass: str | None,
    only_status: str | None,
    degraded_passes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply report filters to mutations and degraded pass rows."""
    mutations = list(all_mutations)
    adjusted_degraded_passes = list(degraded_passes)
    if only_degraded and not degraded_validation:
        mutations = []
    if only_failed_gates and not failed_gates:
        mutations = []
    if only_risky_filters:
        mutations = [mutation for mutation in mutations if mutation.get("pass_name") in selected_risk_pass_names]
    if resolved_only_pass and adjusted_degraded_passes:
        adjusted_degraded_passes = [
            item
            for item in adjusted_degraded_passes
            if item.get("pass_name") == resolved_only_pass or item.get("mutation") == resolved_only_pass
        ]
    if only_risky_filters and adjusted_degraded_passes:
        adjusted_degraded_passes = [
            item
            for item in adjusted_degraded_passes
            if item.get("pass_name", item.get("mutation", "unknown")) in selected_risk_pass_names
        ]
    if resolved_only_pass:
        mutations = [mutation for mutation in mutations if mutation.get("pass_name") == resolved_only_pass]
    if only_status:
        mutations = [
            mutation for mutation in mutations if mutation.get("metadata", {}).get("symbolic_status") == only_status
        ]
    return mutations, adjusted_degraded_passes


def _sort_pass_evidence(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order pass evidence by risk priority for triage."""
    return sorted(
        (row for row in rows if row.get("pass_name")),
        key=lambda row: (
            -int(row.get("symbolic_binary_mismatched_regions", 0)),
            -int(row.get("structural_issue_count", 0)),
            -int(row.get("changed_region_count", 0)),
            -int(row.get("changed_bytes", 0)),
            str(row.get("pass_name", "")),
        ),
    )


def _pass_names_from_triage_rows(
    triage_rows: list[dict[str, Any]],
    *,
    kind: str,
) -> set[str]:
    """Derive pass sets from persisted triage rows when buckets are missing."""
    selected: set[str] = set()
    for row in triage_rows:
        pass_name = str(row.get("pass_name", "")).strip()
        if not pass_name:
            continue
        severity = str(row.get("severity", "not-requested"))
        structural_issue_count = int(row.get("structural_issue_count", 0))
        symbolic_mismatch = int(row.get("symbolic_binary_mismatched_regions", 0))
        symbolic_requested = int(row.get("symbolic_requested", 0))
        without_coverage = int(row.get("without_coverage", 0))
        issue_count = int(row.get("issue_count", 0))
        clean = (
            structural_issue_count == 0
            and symbolic_mismatch == 0
            and severity in {"clean", "not-requested"}
            and issue_count == 0
        )
        covered = clean and symbolic_requested > 0 and without_coverage == 0
        uncovered = clean and not covered
        symbolic_risk = (
            symbolic_mismatch > 0
            or severity
            in {
                "mismatch",
                "without-coverage",
                "bounded-only",
            }
            or issue_count > 0
        )
        structural_risk = structural_issue_count > 0
        risky = symbolic_risk or structural_risk
        if kind == "risky" and risky:
            selected.add(pass_name)
        elif kind == "structural" and structural_risk:
            selected.add(pass_name)
        elif kind == "symbolic" and symbolic_risk:
            selected.add(pass_name)
        elif kind == "clean" and clean:
            selected.add(pass_name)
        elif kind == "covered" and covered:
            selected.add(pass_name)
        elif kind == "uncovered" and uncovered:
            selected.add(pass_name)
    return selected


def _finalize_report_output(
    *,
    filtered_payload: dict[str, Any],
    output: Path | None,
    summary_only: bool,
    require_results: bool,
    min_severity_rank: int | None,
    only_failed_gates: bool,
    failed_gates: bool,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
) -> None:
    """Emit a filtered report and enforce CLI exit policies."""
    filtered_summary = filtered_payload.get("filtered_summary", {})
    _emit_report_payload(
        filtered_payload=filtered_payload,
        output=output,
        summary_only=summary_only,
    )
    _enforce_report_requirements(
        require_results=require_results,
        severity_rows=filtered_summary.get("symbolic_severity_by_pass", []),
        min_severity_rank=min_severity_rank,
        mutation_count=len(filtered_payload.get("mutations", [])),
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        gate_failure_count=(
            int(filtered_summary.get("gate_failures", {}).get("require_pass_severity_failure_count", 0))
            if (only_expected_severity is not None or resolved_only_pass_failure is not None)
            else _gate_failure_result_count(filtered_summary.get("gate_failures", {})) if only_failed_gates else None
        ),
        only_risky_passes=(
            only_risky_passes
            or only_structural_risk
            or only_symbolic_risk
            or only_uncovered_passes
            or only_covered_passes
            or only_clean_passes
        ),
        risky_pass_count=(
            len(filtered_summary.get("passes", []))
            if (
                only_risky_passes
                or only_structural_risk
                or only_symbolic_risk
                or only_uncovered_passes
                or only_covered_passes
                or only_clean_passes
            )
            else len(filtered_summary.get("pass_evidence", []))
        ),
        pass_count=len(filtered_summary.get("passes", [])),
    )


def _attach_gate_evaluation(
    report_payload: dict[str, Any],
    *,
    min_severity: str | None,
    min_severity_passed: bool,
    require_pass_severity: list[tuple[str, str, int]],
    require_pass_severity_passed: bool,
    require_pass_severity_failures: list[str],
) -> dict[str, Any]:
    """Attach CLI gate evaluation metadata to a report payload."""
    gate_evaluation = {
        "requested": {
            "min_severity": min_severity,
            "require_pass_severity": [
                {"pass_name": pass_name, "max_severity": severity}
                for pass_name, severity, _rank in require_pass_severity
            ],
        },
        "results": {
            "min_severity_passed": min_severity_passed,
            "require_pass_severity_passed": require_pass_severity_passed,
            "require_pass_severity_failures": list(require_pass_severity_failures),
            "all_passed": min_severity_passed and require_pass_severity_passed,
        },
    }
    gate_failures = _summarize_gate_failures(gate_evaluation)
    gate_failure_priority = _build_gate_failure_priority(gate_failures)
    gate_failure_severity_priority = _build_gate_failure_severity_priority(gate_failures)
    report_payload["gate_evaluation"] = gate_evaluation
    report_payload["gate_failures"] = gate_failures
    report_payload["gate_failure_priority"] = gate_failure_priority
    report_payload["gate_failure_severity_priority"] = gate_failure_severity_priority
    summary: dict[str, Any] = dict(report_payload.get("summary", {}) or {})
    summary["gate_evaluation"] = gate_evaluation["results"]
    summary["gate_failures"] = gate_failures
    summary["gate_failure_priority"] = gate_failure_priority
    summary["gate_failure_severity_priority"] = gate_failure_severity_priority
    report_payload["summary"] = summary
    return report_payload


def _filter_failed_gates_view(
    *,
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Apply gate filters to the normalized failed-gates view."""
    filtered_summary = dict(gate_failure_summary)
    filtered_priority = list(gate_failure_priority)
    filtered_severity_priority = list(gate_failure_severity_priority)
    if only_expected_severity:
        filtered_severity_priority = [
            row for row in filtered_severity_priority if row.get("severity") == only_expected_severity
        ]
        filtered_priority = [
            row for row in filtered_priority if row.get("strictest_expected_severity") == only_expected_severity
        ]
        filtered_summary["require_pass_severity_failures_by_expected_severity"] = {
            row.get("severity", "unknown"): row.get("failure_count", 0) for row in filtered_severity_priority
        }
    if resolved_only_pass_failure:
        filtered_priority = [row for row in filtered_priority if row.get("pass_name") == resolved_only_pass_failure]
    filtered_summary["require_pass_severity_failures_by_pass"] = {
        row.get("pass_name", "unknown"): list(row.get("failures", [])) for row in filtered_priority
    }
    filtered_summary["require_pass_severity_failures"] = [
        failure for row in filtered_priority for failure in row.get("failures", [])
    ]
    filtered_summary["require_pass_severity_failure_count"] = len(filtered_summary["require_pass_severity_failures"])
    filtered_summary["require_pass_severity_failed"] = bool(filtered_summary["require_pass_severity_failures"])
    if resolved_only_pass_failure:
        severity_counts: dict[str, int] = {}
        for row in filtered_priority:
            severity = row.get("strictest_expected_severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + int(row.get("failure_count", 0))
        filtered_summary["require_pass_severity_failures_by_expected_severity"] = severity_counts
        filtered_severity_priority = _build_gate_failure_severity_priority(filtered_summary)
    filtered_failed = bool(filtered_summary.get("require_pass_severity_failure_count", 0))
    return filtered_summary, filtered_priority, filtered_severity_priority, filtered_failed


def _summarize_symbolic_view_from_mutations(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
) -> tuple[int, int, int, int, int, dict[str, dict[str, int]], list[tuple[str, int | None, int | None, list[str]]]]:
    """Resolve symbolic overview counters using summary first, mutation scan as fallback."""
    symbolic_overview = dict(summary.get("symbolic_overview", {}) or {})
    symbolic_requested = int(symbolic_overview.get("symbolic_requested", 0))
    observable_match = int(symbolic_overview.get("observable_match", 0))
    observable_mismatch = int(symbolic_overview.get("observable_mismatch", 0))
    observable_not_run = int(symbolic_overview.get("without_coverage", 0))
    bounded_only = int(symbolic_overview.get("bounded_only", 0))
    by_pass: dict[str, dict[str, int]] = {}
    mismatch_rows: list[tuple[str, int | None, int | None, list[str]]] = []

    for mutation in mutations:
        pass_name = mutation.get("pass_name", "unknown")
        pass_stats = by_pass.setdefault(
            pass_name,
            {
                "symbolic_requested": 0,
                "observable_match": 0,
                "observable_mismatch": 0,
                "bounded_only": 0,
                "without_coverage": 0,
            },
        )
        metadata = mutation.get("metadata", {})
        if not metadata.get("symbolic_requested"):
            continue
        if not symbolic_overview:
            symbolic_requested += 1
        pass_stats["symbolic_requested"] += 1
        if metadata.get("symbolic_observable_check_performed"):
            if metadata.get("symbolic_observable_equivalent"):
                if not symbolic_overview:
                    observable_match += 1
                pass_stats["observable_match"] += 1
            else:
                if not symbolic_overview:
                    observable_mismatch += 1
                pass_stats["observable_mismatch"] += 1
                mismatch_rows.append(
                    (
                        pass_name,
                        mutation.get("start_address"),
                        mutation.get("end_address"),
                        list(metadata.get("symbolic_observable_mismatches", [])),
                    )
                )
        elif metadata.get("symbolic_status") in {
            "bounded-step-passed",
            "bounded-step-known-equivalence",
            "bounded-step-observables-match",
            "bounded-step-observable-mismatch",
        }:
            if not symbolic_overview:
                bounded_only += 1
            pass_stats["bounded_only"] += 1
        else:
            if not symbolic_overview:
                observable_not_run += 1
            pass_stats["without_coverage"] += 1

    return (
        symbolic_requested,
        observable_match,
        observable_mismatch,
        bounded_only,
        observable_not_run,
        by_pass,
        mismatch_rows,
    )


def _expected_severity_rank_from_failure(failure: str) -> int:
    """Extract expected severity rank from a persisted pass failure string."""
    marker = "expected <= "
    if marker not in failure:
        return 99
    severity = failure.split(marker, 1)[1].rstrip(") ").strip()
    return SEVERITY_ORDER.get(severity, 99)


def _emit_report_payload(
    *,
    filtered_payload: dict[str, Any],
    output: Path | None,
    summary_only: bool,
) -> None:
    """Write and/or print a filtered report payload."""
    if output is not None:
        output.write_text(json.dumps(filtered_payload, indent=2), encoding="utf-8")
        console.print(f"[cyan]Filtered report written:[/cyan] {output}")
    if not summary_only:
        console.print_json(json.dumps(filtered_payload))


def _enforce_report_requirements(
    *,
    require_results: bool,
    severity_rows: list[dict[str, Any]],
    min_severity_rank: int | None,
    mutation_count: int,
    only_failed_gates: bool,
    failed_gates: bool,
    gate_failure_count: int | None,
    only_risky_passes: bool,
    risky_pass_count: int,
    pass_count: int,
) -> None:
    """Apply report exit-code policy for empty views or missing severity."""
    severity_ok = _severity_threshold_met(severity_rows, min_severity_rank)
    has_results = _report_view_has_results(
        mutation_count=mutation_count,
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        gate_failure_count=gate_failure_count,
        only_risky_passes=only_risky_passes,
        risky_pass_count=risky_pass_count,
        pass_count=pass_count,
    )
    if require_results and (not has_results or not severity_ok):
        raise typer.Exit(1)


def _resolve_general_report_views(summary: dict[str, Any]) -> dict[str, Any]:
    """Resolve summary-first general report views with renderer-state fallbacks."""
    summary_report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(summary_report_views.get("general_renderer_state", {}) or {})
    general_summary_view = dict(summary_report_views.get("general_summary", {}) or {})
    general_symbolic_view = dict(summary_report_views.get("general_symbolic", {}) or {})
    general_gates_view = dict(summary_report_views.get("general_gates", {}) or {})
    general_degradation_view = dict(summary_report_views.get("general_degradation", {}) or {})
    general_discards_view = dict(summary_report_views.get("general_discards", {}) or {})
    general_summary_rows = list(
        _first_available(
            list(summary_report_views.get("general_summary_rows", []) or []),
            list(general_renderer_state.get("general_summary_rows", []) or []),
            list(general_renderer_state.get("summary_rows", []) or []),
        )
        or []
    )
    general_summary_view = _first_available(
        general_summary_view,
        dict(general_renderer_state.get("general_summary", {}) or {}),
    )
    if not general_symbolic_view and general_renderer_state.get("general_symbolic"):
        general_symbolic_view = {"overview": dict(general_renderer_state.get("general_symbolic", {}) or {})}
    if not general_gates_view and general_renderer_state.get("general_gates"):
        general_gates_view = {"compact_summary": dict(general_renderer_state.get("general_gates", {}) or {})}
    if not general_degradation_view and general_renderer_state.get("general_degradation"):
        general_degradation_view = {"summary": dict(general_renderer_state.get("general_degradation", {}) or {})}
    if not general_discards_view and general_renderer_state.get("general_discards"):
        general_discards_view = {"summary": dict(general_renderer_state.get("general_discards", {}) or {})}

    return {
        "report_views": summary_report_views,
        "general_renderer_state": general_renderer_state,
        "general_summary_rows": general_summary_rows,
        "general_summary": general_summary_view,
        "general_symbolic": general_symbolic_view,
        "general_gates": general_gates_view,
        "general_degradation": general_degradation_view,
        "general_discards": general_discards_view,
    }


def _resolve_summary_pass_sources(summary: dict[str, Any]) -> dict[str, Any]:
    """Resolve summary-first pass-related sources in one place."""
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    general_renderer_state = resolved_general_views["general_renderer_state"]
    general_renderer_passes = list(general_renderer_state.get("passes", []) or [])
    general_renderer_general_passes = list(general_renderer_state.get("general_passes", []) or [])
    general_renderer_general_pass_rows = list(general_renderer_state.get("general_pass_rows", []) or [])
    general_renderer_pass_rows = list(
        general_renderer_state.get(
            "pass_rows",
            general_renderer_general_pass_rows or general_renderer_general_passes or general_renderer_passes,
        )
        or general_renderer_general_pass_rows
        or general_renderer_general_passes
        or general_renderer_passes
    )
    general_renderer_triage_rows = list(
        general_renderer_state.get(
            "general_triage_rows",
            general_renderer_state.get("triage_rows", []),
        )
        or []
    )
    return {
        "pass_validation_context": dict(summary.get("pass_validation_context", {}) or {}),
        "pass_symbolic_summary": dict(summary.get("pass_symbolic_summary", {}) or {}),
        "pass_capabilities": dict(summary.get("pass_capabilities", {}) or {}),
        "pass_evidence_map": dict(summary.get("pass_evidence_map", {}) or {}),
        "pass_region_evidence_map": dict(summary.get("pass_region_evidence_map", {}) or {}),
        "pass_triage_map": dict(summary.get("pass_triage_map", {}) or {}),
        "normalized_pass_results": list(summary.get("normalized_pass_results", []) or []),
        "symbolic_issue_map": dict(summary.get("symbolic_issue_map", {}) or {}),
        "symbolic_coverage_map": dict(summary.get("symbolic_coverage_map", {}) or {}),
        "symbolic_severity_map": dict(summary.get("symbolic_severity_map", {}) or {}),
        "pass_capability_summary_map": dict(summary.get("pass_capability_summary_map", {}) or {}),
        "validation_role_map": dict(summary.get("validation_role_map", {}) or {}),
        "discarded_mutation_summary": dict(summary.get("discarded_mutation_summary", {}) or {}),
        "discarded_mutation_priority": list(summary.get("discarded_mutation_priority", []) or []),
        "pass_evidence_compact": list(summary.get("pass_evidence_compact", [])),
        "report_views": report_views,
        "discarded_view": dict(report_views.get("discarded_view", {}) or {}),
        "general_passes": list(
            report_views.get("general_passes", []) or general_renderer_general_passes or general_renderer_passes
        ),
        "general_pass_rows": list(report_views.get("general_pass_rows", []) or general_renderer_pass_rows),
        "general_summary": resolved_general_views["general_summary"],
        "general_symbolic": resolved_general_views["general_symbolic"],
        "general_gates": resolved_general_views["general_gates"],
        "general_degradation": resolved_general_views["general_degradation"],
        "general_discards": resolved_general_views["general_discards"],
        "general_triage_rows": list(report_views.get("general_triage_rows", []) or general_renderer_triage_rows),
    }


def _resolve_general_filtered_passes(
    *,
    existing_passes: list[str],
    summary_only_pass_view: dict[str, Any],
    summary_general_passes: list[dict[str, Any]],
    summary_general_pass_rows: list[dict[str, Any]],
    summary_general_summary: dict[str, Any],
    resolved_only_pass: str | None,
    selected_risk_pass_names: set[str],
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_failed_gates: bool,
    gate_failure_priority: list[dict[str, Any]],
) -> list[str]:
    """Resolve the visible pass list for the general report path."""
    resolved_passes = list(existing_passes)
    if not resolved_passes and summary_general_summary.get("passes"):
        resolved_passes = [str(pass_name) for pass_name in list(summary_general_summary.get("passes", [])) if pass_name]
    if not resolved_passes and summary_general_passes:
        resolved_passes = sorted({str(row.get("pass_name")) for row in summary_general_passes if row.get("pass_name")})
    if not resolved_passes and summary_general_pass_rows:
        resolved_passes = sorted(
            {str(row.get("pass_name")) for row in summary_general_pass_rows if row.get("pass_name")}
        )
    if resolved_only_pass and not resolved_passes and resolved_only_pass in summary_only_pass_view:
        resolved_passes = [resolved_only_pass]
    if (
        only_risky_passes
        or only_structural_risk
        or only_symbolic_risk
        or only_uncovered_passes
        or only_covered_passes
        or only_clean_passes
    ):
        return sorted(
            pass_name
            for pass_name in selected_risk_pass_names
            if resolved_only_pass is None or pass_name == resolved_only_pass
        )
    if resolved_only_pass and not resolved_passes:
        # Only include the requested pass when it actually appears in the
        # report data.  If it does not, keep the list empty so that
        # ``--require-results`` can detect that the filtered view is empty.
        all_known = (
            set(existing_passes)
            | {str(row.get("pass_name")) for row in summary_general_passes if row.get("pass_name")}
            | {str(row.get("pass_name")) for row in summary_general_pass_rows if row.get("pass_name")}
            | set(summary_only_pass_view)
        )
        if resolved_only_pass in all_known:
            return [resolved_only_pass]
        return []
    if only_failed_gates and not resolved_passes and gate_failure_priority:
        return sorted({str(row.get("pass_name")) for row in gate_failure_priority if row.get("pass_name")})
    # When filtering to a single pass, restrict the resolved list so that
    # ``--require-results`` correctly detects empty views.
    if resolved_only_pass and resolved_passes:
        return [p for p in resolved_passes if p == resolved_only_pass]
    return resolved_passes
