"""Report helpers: small helper/predicate functions for reporting.

Extracted from cli.py -- no logic changes.
"""

import json
import re
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
        return True
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
            else _gate_failure_result_count(filtered_summary.get("gate_failures", {}))
            if only_failed_gates
            else None
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
    report_payload: dict[str, object],
    *,
    min_severity: str | None,
    min_severity_passed: bool,
    require_pass_severity: list[tuple[str, str, int]],
    require_pass_severity_passed: bool,
    require_pass_severity_failures: list[str],
) -> dict[str, object]:
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
    summary = dict(report_payload.get("summary", {}))
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


def _render_report_filter_messages(
    *,
    only_pass: str | None,
    resolved_only_pass: str | None,
    only_pass_failure: str | None,
    resolved_only_pass_failure: str | None,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    selected_risk_pass_names: set[str],
) -> None:
    """Render compact filter-resolution/status messages."""
    if only_pass is not None and resolved_only_pass != only_pass:
        console.print(f"[bold]Pass Filter Resolution[/bold]: {only_pass} -> {resolved_only_pass}")
    if only_pass_failure is not None and resolved_only_pass_failure != only_pass_failure:
        console.print(
            f"[bold]Pass Failure Filter Resolution[/bold]: {only_pass_failure} -> {resolved_only_pass_failure}"
        )
    if only_risky_passes:
        console.print(f"[bold]Risky Pass Filter[/bold]: {len(selected_risk_pass_names)} risky pass(es) detected")
    if only_uncovered_passes:
        console.print(
            f"[bold]Uncovered Pass Filter[/bold]: {len(selected_risk_pass_names)} uncovered pass(es) detected"
        )
    if only_covered_passes:
        console.print(f"[bold]Covered Pass Filter[/bold]: {len(selected_risk_pass_names)} covered pass(es) detected")
    if only_clean_passes:
        console.print(f"[bold]Clean Pass Filter[/bold]: {len(selected_risk_pass_names)} clean pass(es) detected")
    if only_structural_risk:
        console.print(
            f"[bold]Structural Risk Filter[/bold]: {len(selected_risk_pass_names)} structural-risk pass(es) detected"
        )
    if only_symbolic_risk:
        console.print(
            f"[bold]Symbolic Risk Filter[/bold]: {len(selected_risk_pass_names)} symbolic-risk pass(es) detected"
        )


def _render_only_mismatches_sections(
    *,
    filtered_mutations: list[dict[str, Any]],
    filtered_passes: list[str],
    mismatch_counts_by_pass: dict[str, int],
    mismatch_observables_by_pass: dict[str, list[str]],
    mismatch_pass_context: dict[str, Any],
    mismatch_degraded_passes: list[dict[str, Any]],
    degraded_passes: list[dict[str, Any]],
    degraded_validation: bool,
    requested_validation_mode: str,
    effective_validation_mode: str,
    mismatch_severity_rows: list[dict[str, Any]],
) -> None:
    """Render the textual sections for report --only-mismatches."""
    console.print(f"[bold]Filtered Mismatch Mutations[/bold]: {len(filtered_mutations)}")
    if degraded_validation:
        console.print(
            "[bold]Mismatch Degradation Context[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )
        if mismatch_degraded_passes:
            trigger_names = ", ".join(
                item.get("pass_name", item.get("mutation", "unknown")) for item in mismatch_degraded_passes
            )
            console.print(f"  trigger_passes={trigger_names}")
        elif degraded_passes:
            trigger_names = ", ".join(
                item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes
            )
            console.print(f"  trigger_passes={trigger_names}")
    if mismatch_counts_by_pass:
        console.print("[bold]Mismatch Pass Summary[/bold]:")
        for pass_name in filtered_passes:
            count = mismatch_counts_by_pass.get(pass_name, 0)
            role = mismatch_pass_context.get(pass_name, {}).get("role", "unknown")
            observables = mismatch_observables_by_pass.get(pass_name, [])
            observable_fragment = f", observables={','.join(observables)}" if observables else ""
            console.print(f"  [cyan]{pass_name}[/cyan]: mismatch_count={count}, role={role}{observable_fragment}")
    if mismatch_severity_rows:
        console.print("[bold]Mismatch Severity Priority[/bold]:")
        for row in mismatch_severity_rows:
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"severity={row.get('severity', 'unknown')}, "
                f"issue_count={row.get('issue_count', 0)}, "
                f"symbolic_requested={row.get('symbolic_requested', 0)}"
            )
    if filtered_mutations:
        console.print("[bold]Mismatch Addresses[/bold]:")
        for mutation in filtered_mutations:
            pass_name = mutation.get("pass_name", "unknown")
            start = mutation.get("start_address")
            end = mutation.get("end_address")
            if start is None:
                location = "unknown"
            elif end is None or start == end:
                location = f"0x{start:x}"
            else:
                location = f"0x{start:x}-0x{end:x}"
            observables = mutation.get("metadata", {}).get("symbolic_observable_mismatches", [])
            observable_str = ", ".join(observables) if observables else ""
            console.print(f"  [cyan]{pass_name}[/cyan] @ {location}: {observable_str}")


def _render_symbolic_sections(
    *,
    symbolic_requested: int,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    observable_not_run: int,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
    mismatch_rows: list[tuple[str, int | None, int | None, list[str]]],
) -> None:
    """Render symbolic-report sections from persisted summary first, then fall back."""
    if not symbolic_requested:
        return
    console.print(
        "[bold]Symbolic Mutation Summary[/bold]: "
        f"{observable_match} observable match, "
        f"{observable_mismatch} observable mismatch, "
        f"{bounded_only} bounded-step only, "
        f"{observable_not_run} without symbolic coverage"
    )
    coverage_rows = list(summary.get("symbolic_coverage_by_pass", []))
    if not coverage_rows:
        coverage_rows = [
            pass_result.get("symbolic_summary", {})
            for pass_result in pass_results.values()
            if pass_result.get("symbolic_summary", {}).get("symbolic_requested", 0) > 0
        ]
    if not coverage_rows:
        coverage_rows = [
            {"pass_name": pass_name, **pass_stats}
            for pass_name, pass_stats in by_pass.items()
            if pass_stats["symbolic_requested"] > 0
        ]
    for row in coverage_rows:
        console.print(
            f"  [cyan]{row['pass_name']}[/cyan]: "
            f"{row['observable_match']} match, "
            f"{row['observable_mismatch']} mismatch, "
            f"{row['bounded_only']} bounded-only, "
            f"{row['without_coverage']} without coverage"
        )
    issue_rows = list(summary.get("symbolic_issue_passes", []))
    severity_rows = list(summary.get("symbolic_severity_by_pass", []))
    if not severity_rows:
        issue_severity_map = {row.get("pass_name"): row.get("severity") for row in issue_rows if row.get("pass_name")}
        severity_rows = [
            {
                "pass_name": row.get("pass_name", "unknown"),
                "severity": issue_severity_map.get(row.get("pass_name")) or row.get("severity", "not-requested"),
                "issue_count": row.get("issue_count", 0),
                "symbolic_requested": row.get("symbolic_requested", 0),
            }
            for row in coverage_rows
        ]
    if not severity_rows and issue_rows:
        severity_rows = [
            {
                "pass_name": row.get("pass_name", "unknown"),
                "severity": row.get("severity", "not-requested"),
                "issue_count": row.get("issue_count", 0),
                "symbolic_requested": row.get("symbolic_requested", 0),
            }
            for row in issue_rows
        ]
    if not severity_rows:
        severity_rows = [
            {
                "pass_name": pass_name,
                "severity": (
                    "mismatch"
                    if pass_stats["observable_mismatch"] > 0
                    else "without-coverage"
                    if pass_stats["without_coverage"] > 0
                    else "bounded-only"
                ),
                "issue_count": (
                    pass_stats["observable_mismatch"] + pass_stats["without_coverage"] + pass_stats["bounded_only"]
                ),
                "symbolic_requested": pass_stats["symbolic_requested"],
            }
            for pass_name, pass_stats in by_pass.items()
            if pass_stats["symbolic_requested"] > 0
        ]
        severity_rows.sort(key=lambda item: item["pass_name"])
    if severity_rows:
        console.print("[bold]Severity Priority[/bold]:")
        for row in severity_rows:
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"severity={row['severity']}, "
                f"issue_count={row.get('issue_count', 0)}, "
                f"symbolic_requested={row.get('symbolic_requested', 0)}"
            )
    if not issue_rows:
        issue_rows = [
            {
                "pass_name": pass_name,
                "severity": (
                    "mismatch"
                    if pass_stats["observable_mismatch"] > 0
                    else "without-coverage"
                    if pass_stats["without_coverage"] > 0
                    else "bounded-only"
                ),
                "observable_mismatch": pass_stats["observable_mismatch"],
                "without_coverage": pass_stats["without_coverage"],
                "bounded_only": pass_stats["bounded_only"],
            }
            for pass_name, pass_stats in by_pass.items()
            if pass_stats["observable_mismatch"] > 0
            or pass_stats["without_coverage"] > 0
            or pass_stats["bounded_only"] > 0
        ]
        issue_rows.sort(
            key=lambda item: (
                -item["observable_mismatch"],
                -item["without_coverage"],
                -item["bounded_only"],
                item["pass_name"],
            )
        )
    if issue_rows:
        console.print("[bold]Passes With Symbolic Issues[/bold]:")
        for row in issue_rows:
            severity = row["severity"]
            if severity_rows:
                severity = next(
                    (
                        item.get("severity", severity)
                        for item in severity_rows
                        if item.get("pass_name") == row["pass_name"]
                    ),
                    severity,
                )
            console.print(
                f"  [yellow]{row['pass_name']}[/yellow]: "
                f"severity={severity}, "
                f"mismatch={row['observable_mismatch']}, "
                f"without_coverage={row['without_coverage']}, "
                f"bounded_only={row['bounded_only']}"
            )
    triage_rows = list(summary.get("pass_triage_rows", []))
    if triage_rows:
        console.print("[bold]Pass Triage[/bold]:")
        for row in triage_rows:
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"severity={row.get('severity', 'unknown')}, "
                f"structural_issues={row.get('structural_issue_count', 0)}, "
                f"symbolic_mismatch={row.get('symbolic_binary_mismatched_regions', 0)}, "
                f"role={row.get('role', 'unknown')}, "
                f"symbolic_confidence={row.get('symbolic_confidence', 'unknown')}"
            )
    pass_evidence_rows = list(summary.get("pass_evidence_compact", []))
    pass_evidence_priority_rows = list(summary.get("pass_evidence_priority", []))
    if pass_evidence_priority_rows:
        pass_evidence_rows = [dict(row) for row in pass_evidence_priority_rows if row.get("pass_name")]
    elif not pass_evidence_rows:
        pass_evidence_rows = _sort_pass_evidence(
            [row for row in list(summary.get("pass_evidence", [])) if row.get("pass_name")]
        )
    if not pass_evidence_rows:
        pass_evidence_rows = _sort_pass_evidence(
            [
                dict(pass_results.get(pass_name, {}).get("evidence_summary", {}))
                for pass_name in sorted(pass_results)
                if pass_results.get(pass_name, {}).get("evidence_summary")
            ]
        )
    if pass_evidence_rows:
        console.print("[bold]Pass Evidence[/bold]:")
        for row in pass_evidence_rows:
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"changed_regions={row.get('changed_region_count', 0)}, "
                f"structural_issues={row.get('structural_issue_count', 0)}, "
                f"symbolic_checked={row.get('symbolic_binary_regions_checked', 0)}, "
                f"symbolic_mismatch={row.get('symbolic_binary_mismatched_regions', 0)}"
            )
    capability_rows = list(summary.get("pass_capability_summary", []))
    if capability_rows:
        console.print("[bold]Pass Capabilities[/bold]:")
        for row in capability_rows:
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"runtime_recommended={str(row.get('runtime_recommended', False)).lower()}, "
                f"symbolic_recommended={str(row.get('symbolic_recommended', False)).lower()}, "
                f"symbolic_confidence={row.get('symbolic_confidence', 'unknown')}"
            )
    discarded_priority = list(summary.get("discarded_mutation_priority", []))
    discarded_summary = dict(summary.get("discarded_mutation_summary", {}) or {})
    if discarded_priority or discarded_summary.get("by_pass"):
        console.print("[bold]Discarded Mutations[/bold]:")
        for row in discarded_priority or discarded_summary["by_pass"]:
            reasons = ",".join(f"{reason}:{count}" for reason, count in dict(row.get("reasons", {})).items())
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"discarded={row.get('discarded_count', 0)}" + (f", reasons={reasons}" if reasons else "")
            )
    if mismatch_rows:
        console.print("[bold]Symbolic Mismatches[/bold]:")
        for pass_name, start, end, observables in mismatch_rows:
            if start is None or end is None:
                location = "unknown"
            elif start == end:
                location = f"0x{start:x}"
            else:
                location = f"0x{start:x}-0x{end:x}"
            details = ", ".join(observables) if observables else "unknown"
            console.print(f"  [red]{pass_name}[/red] @ {location}: {details}")


def _render_degradation_sections(
    *,
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    validation_policy: dict[str, Any] | None,
    degraded_passes: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    symbolic_severity_rows: list[dict[str, Any]],
) -> None:
    """Render validation-mode adjustment/degradation summary."""
    if degraded_validation:
        console.print(
            "[bold]Validation Mode Adjustment[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )
        if validation_policy is not None:
            console.print(
                f"  policy={validation_policy.get('policy', 'unknown')}, "
                f"reason={validation_policy.get('reason', 'unknown')}"
            )
            if degraded_passes:
                console.print("[bold]Degraded Passes[/bold]:")
                for item in degraded_passes:
                    pass_name = item.get("pass_name", item.get("mutation", "unknown"))
                    confidence = item.get("confidence", "unknown")
                    console.print(f"  [yellow]{pass_name}[/yellow]: symbolic confidence={confidence}")
            if degradation_roles:
                console.print("[bold]Degradation Roles[/bold]:")
                for role, count in sorted(degradation_roles.items()):
                    console.print(f"  {role}: {count}")
            if symbolic_severity_rows:
                console.print("[bold]Degraded Severity Priority[/bold]:")
                for row in symbolic_severity_rows:
                    console.print(
                        f"  [cyan]{row['pass_name']}[/cyan]: "
                        f"severity={row.get('severity', 'unknown')}, "
                        f"issue_count={row.get('issue_count', 0)}, "
                        f"symbolic_requested={row.get('symbolic_requested', 0)}"
                    )
    elif requested_validation_mode:
        console.print(
            "[bold]Validation Mode[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )


def _render_gate_sections(
    *,
    gate_evaluation: dict[str, Any],
    gate_requested: dict[str, Any],
    gate_results: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
) -> None:
    """Render persisted gate evaluation and failure sections."""
    if not gate_evaluation:
        return
    console.print(f"[bold]Gate Evaluation[/bold]: all_passed={'yes' if gate_results.get('all_passed', True) else 'no'}")
    if gate_requested.get("min_severity") is not None:
        console.print(
            "  "
            f"min_severity={gate_requested.get('min_severity')}, "
            f"passed={'yes' if gate_results.get('min_severity_passed', True) else 'no'}"
        )
    if gate_requested.get("require_pass_severity"):
        requested_rules = ", ".join(
            f"{item.get('pass_name')}<={item.get('max_severity')}"
            for item in gate_requested.get("require_pass_severity", [])
        )
        console.print(
            "  "
            f"require_pass_severity={requested_rules}, "
            f"passed={'yes' if gate_results.get('require_pass_severity_passed', True) else 'no'}"
        )
        failures = list(gate_results.get("require_pass_severity_failures", []))
        if failures:
            console.print("  failures: " + ", ".join(failures))
    console.print(
        "[bold]Gate Failure Summary[/bold]: "
        f"min_severity_failed={'yes' if gate_failure_summary.get('min_severity_failed') else 'no'}, "
        f"require_pass_failures={gate_failure_summary.get('require_pass_severity_failure_count', 0)}"
    )
    severity_counts = gate_failure_summary.get("require_pass_severity_failures_by_expected_severity", {})
    if severity_counts:
        console.print(
            "  expected_severity_counts="
            + ", ".join(f"{severity}:{count}" for severity, count in severity_counts.items())
        )
    if gate_failure_severity_priority:
        console.print(
            "  expected_severity_priority="
            + ", ".join(f"{row.get('severity')}:{row.get('failure_count')}" for row in gate_failure_severity_priority)
        )
    pass_failure_map = gate_failure_summary.get("require_pass_severity_failures_by_pass", {})
    if pass_failure_map:
        console.print("[bold]Gate Failure By Pass[/bold]:")
        for row in gate_failure_priority or [
            {
                "pass_name": pass_name,
                "failure_count": len(failures),
                "strictest_expected_severity": "unknown",
                "failures": list(failures),
            }
            for pass_name, failures in pass_failure_map.items()
        ]:
            pass_name = row.get("pass_name", "unknown")
            failures = list(row.get("failures", []))
            failure_count = row.get("failure_count", len(failures))
            strictest = row.get("strictest_expected_severity", "unknown")
            console.print(
                f"  [yellow]{pass_name}[/yellow] "
                f"(count={failure_count}, strictest_expected={strictest}): " + ", ".join(failures)
            )


def _render_pass_capabilities(
    *,
    filtered_summary: dict[str, Any],
) -> None:
    """Render pass capabilities for visible passes."""
    if not filtered_summary.get("pass_capabilities"):
        return
    console.print("[bold]Pass Capabilities[/bold]:")
    for pass_name in filtered_summary.get("passes", []):
        capabilities = filtered_summary["pass_capabilities"].get(pass_name)
        if not capabilities:
            continue
        runtime = capabilities.get("runtime", {})
        symbolic = capabilities.get("symbolic", {})
        runtime_recommended = runtime.get("recommended")
        symbolic_confidence = symbolic.get("confidence")
        symbolic_recommended = symbolic.get("recommended")
        fragments = []
        if runtime_recommended is not None:
            fragments.append(f"runtime recommended={'yes' if runtime_recommended else 'no'}")
        if symbolic_confidence:
            fragments.append(f"symbolic confidence={symbolic_confidence}")
        if symbolic_recommended is not None:
            fragments.append(f"symbolic recommended={'yes' if symbolic_recommended else 'no'}")
        if fragments:
            console.print(f"  [cyan]{pass_name}[/cyan]: " + ", ".join(fragments))


def _render_pass_validation_contexts(
    *,
    filtered_summary: dict[str, Any],
    pass_results: dict[str, Any],
    degraded_passes: list[dict[str, Any]],
) -> None:
    """Render pass validation contexts for visible passes."""
    relevant_contexts = []
    context_pass_names = list(filtered_summary.get("passes", []))
    if not context_pass_names and degraded_passes:
        context_pass_names = [item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes]
    for pass_name in context_pass_names:
        context = filtered_summary.get("pass_validation_context", {}).get(pass_name)
        if context is None:
            raw_context = pass_results.get(pass_name, {}).get("validation_context")
            if raw_context:
                context = dict(raw_context)
                context["role"] = (
                    "degradation-trigger"
                    if context.get("degradation_triggered_by_pass")
                    else "executed-under-degraded-mode"
                    if context.get("degraded_execution")
                    else "requested-mode"
                )
                filtered_summary.setdefault("pass_validation_context", {})[pass_name] = context
        if context:
            relevant_contexts.append((pass_name, context))
    if relevant_contexts:
        console.print("[bold]Pass Validation Context[/bold]:")
        for pass_name, context in relevant_contexts:
            _render_pass_validation_context(pass_name, context)


def _render_pass_validation_context(
    pass_name: str,
    context: dict[str, Any],
) -> None:
    """Render one compact pass validation context block."""
    fragments = [
        f"requested={context.get('requested_validation_mode', 'unknown')}",
        f"effective={context.get('effective_validation_mode', 'unknown')}",
    ]
    if context.get("degraded_execution"):
        fragments.append("degraded=yes")
    if context.get("degradation_triggered_by_pass"):
        fragments.append("trigger=yes")
        fragments.append("role=degradation-trigger")
    elif context.get("degraded_execution"):
        fragments.append("role=executed-under-degraded-mode")
    else:
        fragments.append(f"role={context.get('role', 'requested-mode')}")
    console.print(f"  [cyan]{pass_name}[/cyan]: " + ", ".join(fragments))


def _render_only_pass_sections(
    *,
    pass_name: str,
    pass_symbolic_summary: dict[str, Any] | None,
    pass_evidence: dict[str, Any] | None,
    pass_validation_context: dict[str, Any] | None,
    pass_region_evidence: list[dict[str, Any]] | None = None,
    pass_capabilities: dict[str, Any] | None = None,
) -> None:
    """Render summary blocks for a single filtered pass."""
    if pass_symbolic_summary and pass_symbolic_summary.get("symbolic_requested", 0) > 0:
        console.print("[bold]Pass Symbolic Summary[/bold]:")
        console.print(
            "  "
            f"[cyan]{pass_name}[/cyan]: "
            f"{pass_symbolic_summary.get('observable_match', 0)} match, "
            f"{pass_symbolic_summary.get('observable_mismatch', 0)} mismatch, "
            f"{pass_symbolic_summary.get('bounded_only', 0)} bounded-only, "
            f"{pass_symbolic_summary.get('without_coverage', 0)} without coverage"
        )
        console.print(
            "  "
            f"severity={pass_symbolic_summary.get('severity', 'unknown')}, "
            f"issue_count={pass_symbolic_summary.get('issue_count', 0)}"
        )
        issues_list = pass_symbolic_summary.get("issues", [])
        if issues_list:
            issues_by_severity: dict[str, dict[str, int]] = {}
            for issue in issues_list:
                sev = issue.get("severity", "unknown")
                if sev not in issues_by_severity:
                    issues_by_severity[sev] = {"mismatch": 0, "without_coverage": 0, "bounded_only": 0}
                issues_by_severity[sev]["mismatch"] += issue.get("observable_mismatch", 0)
                issues_by_severity[sev]["without_coverage"] += issue.get("without_coverage", 0)
                issues_by_severity[sev]["bounded_only"] += issue.get("bounded_only", 0)
            for sev, counts in issues_by_severity.items():
                console.print(
                    "  "
                    f"issues: {sev}(mismatch={counts['mismatch']}, "
                    f"without_coverage={counts['without_coverage']}, "
                    f"bounded_only={counts['bounded_only']})"
                )
    if pass_evidence:
        console.print("[bold]Pass Evidence Summary[/bold]:")
        console.print(
            "  "
            f"[cyan]{pass_name}[/cyan]: "
            f"changed_regions={pass_evidence.get('changed_region_count', 0)}, "
            f"changed_bytes={pass_evidence.get('changed_bytes', 0)}, "
            f"structural_issues={pass_evidence.get('structural_issue_count', 0)}, "
            f"symbolic_checked={pass_evidence.get('symbolic_binary_regions_checked', 0)}, "
            f"symbolic_mismatch={pass_evidence.get('symbolic_binary_mismatched_regions', 0)}"
        )
    if pass_region_evidence:
        console.print("[bold]Pass Region Evidence[/bold]:")
        for row in pass_region_evidence[:5]:
            start = row.get("start_address")
            end = row.get("end_address")
            if start is None or end is None:
                region = "unknown"
            elif start == end:
                region = f"0x{start:x}"
            else:
                region = f"0x{start:x}-0x{end:x}"
            console.print(
                "  "
                f"[cyan]{region}[/cyan]: "
                f"equivalent={str(bool(row.get('equivalent', False))).lower()}, "
                f"mismatch_count={row.get('mismatch_count', 0)}, "
                f"step={row.get('step_strategy', 'unknown')}, "
                f"trace={row.get('original_trace_length', 0)}/{row.get('mutated_trace_length', 0)}"
            )
    if pass_validation_context:
        console.print("[bold]Pass Validation Context[/bold]:")
        _render_pass_validation_context(pass_name, pass_validation_context)
    if pass_capabilities:
        console.print("[bold]Pass Capabilities[/bold]:")
        fragments = []
        if pass_capabilities.get("runtime_recommended") is not None:
            fragments.append(f"runtime recommended={'yes' if pass_capabilities.get('runtime_recommended') else 'no'}")
        if pass_capabilities.get("symbolic_confidence"):
            fragments.append(f"symbolic confidence={pass_capabilities.get('symbolic_confidence')}")
        if pass_capabilities.get("symbolic_recommended") is not None:
            fragments.append(f"symbolic recommended={'yes' if pass_capabilities.get('symbolic_recommended') else 'no'}")
        if fragments:
            console.print(f"  [cyan]{pass_name}[/cyan]: " + ", ".join(fragments))


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
    general_summary_rows = list(summary_report_views.get("general_summary_rows", []) or [])

    if not general_summary_rows and general_renderer_state.get("general_summary_rows"):
        general_summary_rows = list(general_renderer_state.get("general_summary_rows", []) or [])
    if not general_summary_rows and general_renderer_state.get("summary_rows"):
        general_summary_rows = list(general_renderer_state.get("summary_rows", []) or [])
    if not general_summary_view and general_renderer_state.get("general_summary"):
        general_summary_view = dict(general_renderer_state.get("general_summary", {}) or {})
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


