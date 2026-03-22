"""CLI-specific rendering functions for report output.

These functions use Rich console to render detailed report sections.
Extracted from report_helpers.py to maintain cohesion."""

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


