"""CLI-specific rendering functions for report output.

These functions use Rich console to render detailed report sections.
Extracted from report_helpers.py to maintain cohesion.

Report helpers: small helper/predicate functions for reporting.
Extracted from cli.py -- no logic changes.
"""

from typing import Any

from rich.console import Console
from rich.table import Table

from r2morph.reporting.report_helpers import _sort_pass_evidence

_console: Console | None = None


def _get_console() -> Console:
    global _console
    if _console is None:
        _console = Console()
    return _console


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
        _get_console().print(f"[bold]Pass Filter Resolution[/bold]: {only_pass} -> {resolved_only_pass}")
    if only_pass_failure is not None and resolved_only_pass_failure != only_pass_failure:
        _get_console().print(
            f"[bold]Pass Failure Filter Resolution[/bold]: {only_pass_failure} -> {resolved_only_pass_failure}"
        )
    if only_risky_passes:
        _get_console().print(f"[bold]Risky Pass Filter[/bold]: {len(selected_risk_pass_names)} risky pass(es) detected")
    if only_uncovered_passes:
        _get_console().print(
            f"[bold]Uncovered Pass Filter[/bold]: {len(selected_risk_pass_names)} uncovered pass(es) detected"
        )
    if only_covered_passes:
        _get_console().print(
            f"[bold]Covered Pass Filter[/bold]: {len(selected_risk_pass_names)} covered pass(es) detected"
        )
    if only_clean_passes:
        _get_console().print(f"[bold]Clean Pass Filter[/bold]: {len(selected_risk_pass_names)} clean pass(es) detected")
    if only_structural_risk:
        _get_console().print(
            f"[bold]Structural Risk Filter[/bold]: {len(selected_risk_pass_names)} structural-risk pass(es) detected"
        )
    if only_symbolic_risk:
        _get_console().print(
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
    _get_console().print(f"[bold]Filtered Mismatch Mutations[/bold]: {len(filtered_mutations)}")
    if degraded_validation:
        _get_console().print(
            "[bold]Mismatch Degradation Context[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )
        if mismatch_degraded_passes:
            trigger_names = ", ".join(
                item.get("pass_name", item.get("mutation", "unknown")) for item in mismatch_degraded_passes
            )
            _get_console().print(f"  trigger_passes={trigger_names}")
        elif degraded_passes:
            trigger_names = ", ".join(
                item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes
            )
            _get_console().print(f"  trigger_passes={trigger_names}")
    if mismatch_counts_by_pass:
        _get_console().print("[bold]Mismatch Pass Summary[/bold]:")
        for pass_name in filtered_passes:
            count = mismatch_counts_by_pass.get(pass_name, 0)
            role = mismatch_pass_context.get(pass_name, {}).get("role", "unknown")
            observables = mismatch_observables_by_pass.get(pass_name, [])
            observable_fragment = f", observables={','.join(observables)}" if observables else ""
            _get_console().print(
                f"  [cyan]{pass_name}[/cyan]: mismatch_count={count}, role={role}{observable_fragment}"
            )
    if mismatch_severity_rows:
        _get_console().print("[bold]Mismatch Severity Priority[/bold]:")
        for row in mismatch_severity_rows:
            _get_console().print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"severity={row.get('severity', 'unknown')}, "
                f"issue_count={row.get('issue_count', 0)}, "
                f"symbolic_requested={row.get('symbolic_requested', 0)}"
            )
    if filtered_mutations:
        _get_console().print("[bold]Mismatch Addresses[/bold]:")
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
            _get_console().print(f"  [cyan]{pass_name}[/cyan] @ {location}: {observable_str}")


def _render_match_table(
    *,
    console: Console,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    observable_not_run: int,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    """Render the symbolic match/coverage overview and return resolved coverage_rows."""
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
    return coverage_rows


def _render_mismatch_table(
    *,
    console: Console,
    summary: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
    coverage_rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Render severity priority and issue rows; return (severity_rows, issue_rows)."""
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
                    else "without-coverage" if pass_stats["without_coverage"] > 0 else "bounded-only"
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
                    else "without-coverage" if pass_stats["without_coverage"] > 0 else "bounded-only"
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
    return severity_rows, issue_rows


def _render_coverage_table(
    *,
    console: Console,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    mismatch_rows: list[tuple[str, int | None, int | None, list[str]]],
) -> None:
    """Render triage, evidence, capabilities, discarded mutations, and mismatch details."""
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
    console = _get_console()
    coverage_rows = _render_match_table(
        console=console,
        observable_match=observable_match,
        observable_mismatch=observable_mismatch,
        bounded_only=bounded_only,
        observable_not_run=observable_not_run,
        summary=summary,
        pass_results=pass_results,
        by_pass=by_pass,
    )
    _render_mismatch_table(
        console=console,
        summary=summary,
        by_pass=by_pass,
        coverage_rows=coverage_rows,
    )
    _render_coverage_table(
        console=console,
        summary=summary,
        pass_results=pass_results,
        mismatch_rows=mismatch_rows,
    )


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
        _get_console().print(
            "[bold]Validation Mode Adjustment[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )
        if validation_policy is not None:
            _get_console().print(
                f"  policy={validation_policy.get('policy', 'unknown')}, "
                f"reason={validation_policy.get('reason', 'unknown')}"
            )
            if degraded_passes:
                _get_console().print("[bold]Degraded Passes[/bold]:")
                for item in degraded_passes:
                    pass_name = item.get("pass_name", item.get("mutation", "unknown"))
                    confidence = item.get("confidence", "unknown")
                    _get_console().print(f"  [yellow]{pass_name}[/yellow]: symbolic confidence={confidence}")
            if degradation_roles:
                _get_console().print("[bold]Degradation Roles[/bold]:")
                for role, count in sorted(degradation_roles.items()):
                    _get_console().print(f"  {role}: {count}")
            if symbolic_severity_rows:
                _get_console().print("[bold]Degraded Severity Priority[/bold]:")
                for row in symbolic_severity_rows:
                    _get_console().print(
                        f"  [cyan]{row['pass_name']}[/cyan]: "
                        f"severity={row.get('severity', 'unknown')}, "
                        f"issue_count={row.get('issue_count', 0)}, "
                        f"symbolic_requested={row.get('symbolic_requested', 0)}"
                    )
    elif requested_validation_mode:
        _get_console().print(
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
    _get_console().print(
        f"[bold]Gate Evaluation[/bold]: all_passed={'yes' if gate_results.get('all_passed', True) else 'no'}"
    )
    if gate_requested.get("min_severity") is not None:
        _get_console().print(
            "  "
            f"min_severity={gate_requested.get('min_severity')}, "
            f"passed={'yes' if gate_results.get('min_severity_passed', True) else 'no'}"
        )
    if gate_requested.get("require_pass_severity"):
        requested_rules = ", ".join(
            f"{item.get('pass_name')}<={item.get('max_severity')}"
            for item in gate_requested.get("require_pass_severity", [])
        )
        _get_console().print(
            "  "
            f"require_pass_severity={requested_rules}, "
            f"passed={'yes' if gate_results.get('require_pass_severity_passed', True) else 'no'}"
        )
        failures = list(gate_results.get("require_pass_severity_failures", []))
        if failures:
            _get_console().print("  failures: " + ", ".join(failures))
    _get_console().print(
        "[bold]Gate Failure Summary[/bold]: "
        f"min_severity_failed={'yes' if gate_failure_summary.get('min_severity_failed') else 'no'}, "
        f"require_pass_failures={gate_failure_summary.get('require_pass_severity_failure_count', 0)}"
    )
    severity_counts = gate_failure_summary.get("require_pass_severity_failures_by_expected_severity", {})
    if severity_counts:
        _get_console().print(
            "  expected_severity_counts="
            + ", ".join(f"{severity}:{count}" for severity, count in severity_counts.items())
        )
    if gate_failure_severity_priority:
        _get_console().print(
            "  expected_severity_priority="
            + ", ".join(f"{row.get('severity')}:{row.get('failure_count')}" for row in gate_failure_severity_priority)
        )
    pass_failure_map = gate_failure_summary.get("require_pass_severity_failures_by_pass", {})
    if pass_failure_map:
        _get_console().print("[bold]Gate Failure By Pass[/bold]:")
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
            _get_console().print(
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
    _get_console().print("[bold]Pass Capabilities[/bold]:")
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
            _get_console().print(f"  [cyan]{pass_name}[/cyan]: " + ", ".join(fragments))


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
                    else "executed-under-degraded-mode" if context.get("degraded_execution") else "requested-mode"
                )
                filtered_summary.setdefault("pass_validation_context", {})[pass_name] = context
        if context:
            relevant_contexts.append((pass_name, context))
    if relevant_contexts:
        _get_console().print("[bold]Pass Validation Context[/bold]:")
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
    _get_console().print(f"  [cyan]{pass_name}[/cyan]: " + ", ".join(fragments))


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
        _get_console().print("[bold]Pass Symbolic Summary[/bold]:")
        _get_console().print(
            "  "
            f"[cyan]{pass_name}[/cyan]: "
            f"{pass_symbolic_summary.get('observable_match', 0)} match, "
            f"{pass_symbolic_summary.get('observable_mismatch', 0)} mismatch, "
            f"{pass_symbolic_summary.get('bounded_only', 0)} bounded-only, "
            f"{pass_symbolic_summary.get('without_coverage', 0)} without coverage"
        )
        _get_console().print(
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
                _get_console().print(
                    "  "
                    f"issues: {sev}(mismatch={counts['mismatch']}, "
                    f"without_coverage={counts['without_coverage']}, "
                    f"bounded_only={counts['bounded_only']})"
                )
    if pass_evidence:
        _get_console().print("[bold]Pass Evidence Summary[/bold]:")
        _get_console().print(
            "  "
            f"[cyan]{pass_name}[/cyan]: "
            f"changed_regions={pass_evidence.get('changed_region_count', 0)}, "
            f"changed_bytes={pass_evidence.get('changed_bytes', 0)}, "
            f"structural_issues={pass_evidence.get('structural_issue_count', 0)}, "
            f"symbolic_checked={pass_evidence.get('symbolic_binary_regions_checked', 0)}, "
            f"symbolic_mismatch={pass_evidence.get('symbolic_binary_mismatched_regions', 0)}"
        )
    if pass_region_evidence:
        _get_console().print("[bold]Pass Region Evidence[/bold]:")
        for row in pass_region_evidence[:5]:
            start = row.get("start_address")
            end = row.get("end_address")
            if start is None or end is None:
                region = "unknown"
            elif start == end:
                region = f"0x{start:x}"
            else:
                region = f"0x{start:x}-0x{end:x}"
            _get_console().print(
                "  "
                f"[cyan]{region}[/cyan]: "
                f"equivalent={str(bool(row.get('equivalent', False))).lower()}, "
                f"mismatch_count={row.get('mismatch_count', 0)}, "
                f"step={row.get('step_strategy', 'unknown')}, "
                f"trace={row.get('original_trace_length', 0)}/{row.get('mutated_trace_length', 0)}"
            )
    if pass_validation_context:
        _get_console().print("[bold]Pass Validation Context[/bold]:")
        _render_pass_validation_context(pass_name, pass_validation_context)
    if pass_capabilities:
        _get_console().print("[bold]Pass Capabilities[/bold]:")
        fragments = []
        if pass_capabilities.get("runtime_recommended") is not None:
            fragments.append(f"runtime recommended={'yes' if pass_capabilities.get('runtime_recommended') else 'no'}")
        if pass_capabilities.get("symbolic_confidence"):
            fragments.append(f"symbolic confidence={pass_capabilities.get('symbolic_confidence')}")
        if pass_capabilities.get("symbolic_recommended") is not None:
            fragments.append(f"symbolic recommended={'yes' if pass_capabilities.get('symbolic_recommended') else 'no'}")
        if fragments:
            _get_console().print(f"  [cyan]{pass_name}[/cyan]: " + ", ".join(fragments))


# ---------------------------------------------------------------------------
# Functions merged from console_renderer.py
# ---------------------------------------------------------------------------

# Backward-compatible alias; prefer _get_console() for lazy initialization.


class _LazyConsole:
    """Thin proxy so ``CONSOLE.print(...)`` keeps working."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_get_console(), name)


CONSOLE = _LazyConsole()


def create_table(title: str, columns: list[tuple[str, str]]) -> Table:
    """
    Create a styled table with columns.

    Args:
        title: Table title
        columns: List of (column_name, style) tuples

    Returns:
        Configured Table instance
    """
    table = Table(title=title)
    for name, style in columns:
        table.add_column(name, style=style)
    return table


def render_pass_capabilities(
    capabilities: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render pass capabilities table.

    Args:
        capabilities: List of capability dictionaries
        console: Optional console instance (uses default if None)
    """
    if not capabilities:
        return

    c = console or _get_console()
    table = create_table(
        "Pass Capabilities",
        [
            ("Pass", "cyan"),
            ("Category", "blue"),
            ("Support", "green"),
        ],
    )

    for cap in capabilities:
        table.add_row(
            cap.get("pass_name", "unknown"),
            cap.get("category", "unknown"),
            cap.get("support", "unknown"),
        )

    c.print(table)


def render_pass_validation_contexts(
    contexts: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render pass validation contexts table.

    Args:
        contexts: List of validation context dictionaries
        console: Optional console instance
    """
    if not contexts:
        return

    c = console or _get_console()
    table = create_table(
        "Pass Validation Contexts",
        [
            ("Pass", "cyan"),
            ("Mode", "blue"),
            ("Degraded", "yellow"),
            ("Gate Failures", "red"),
        ],
    )

    for ctx in contexts:
        table.add_row(
            ctx.get("pass_name", "unknown"),
            ctx.get("validation_mode", "unknown"),
            "Yes" if ctx.get("degraded_execution") else "No",
            str(ctx.get("gate_failure_count", 0)),
        )

    c.print(table)


def render_symbolic_sections(
    symbolic_requested: int,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    without_coverage: int,
    *,
    console: Console | None = None,
) -> None:
    """
    Render symbolic validation summary.

    Args:
        symbolic_requested: Total symbolic regions checked
        observable_match: Observable match count
        observable_mismatch: Observable mismatch count
        bounded_only: Bounded only count
        without_coverage: Without coverage count
        console: Optional console instance
    """
    if symbolic_requested == 0:
        return

    c = console or _get_console()
    table = create_table(
        "Symbolic Validation Summary",
        [
            ("Metric", "cyan"),
            ("Count", "green"),
        ],
    )

    table.add_row("Symbolic Regions Checked", str(symbolic_requested))
    table.add_row("Observable Match", str(observable_match))
    table.add_row("Observable Mismatch", str(observable_mismatch))
    table.add_row("Bounded Only", str(bounded_only))
    table.add_row("Without Coverage", str(without_coverage))

    c.print(table)


def render_gate_sections(
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render gate failure summary.

    Args:
        gate_failure_summary: Gate failure summary dict
        gate_failure_priority: Priority ordered gate failures
        console: Optional console instance
    """
    c = console or _get_console()

    if not gate_failure_summary.get("require_pass_severity_failure_count", 0):
        c.print("[green]All gate checks passed[/green]")
        return

    table = create_table(
        "Gate Failures",
        [
            ("Pass", "cyan"),
            ("Failure Count", "red"),
            ("Strictest Severity", "yellow"),
        ],
    )

    for row in gate_failure_priority:
        table.add_row(
            row.get("pass_name", "unknown"),
            str(row.get("failure_count", 0)),
            row.get("strictest_expected_severity", "unknown"),
        )

    c.print(table)


def render_degradation_sections(
    degradation_summary: dict[str, Any],
    *,
    console: Console | None = None,
) -> None:
    """
    Render validation mode degradation summary.

    Args:
        degradation_summary: Degradation summary dict
        console: Optional console instance
    """
    c = console or _get_console()

    if not degradation_summary.get("degraded_validation"):
        return

    table = create_table(
        "Validation Mode Degradation",
        [
            ("Role", "cyan"),
            ("Count", "yellow"),
        ],
    )

    for role, count in degradation_summary.get("roles", {}).items():
        table.add_row(role, str(count))

    c.print(table)


def render_only_mismatches_sections(
    mismatch_rows: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render only-mismatches report sections.

    Args:
        mismatch_rows: List of mismatch row dictionaries
        console: Optional console instance
    """
    if not mismatch_rows:
        return

    c = console or _get_console()
    table = create_table(
        "Observable Mismatches by Pass",
        [
            ("Pass", "cyan"),
            ("Mismatch Count", "red"),
            ("Regions Checked", "blue"),
        ],
    )

    for row in mismatch_rows:
        table.add_row(
            row.get("pass_name", "unknown"),
            str(row.get("mismatch_count", 0)),
            str(row.get("region_count", 0)),
        )

    c.print(table)


def render_only_pass_sections(
    pass_name: str,
    pass_data: dict[str, Any],
    *,
    console: Console | None = None,
) -> None:
    """
    Render sections for a single pass.

    Args:
        pass_name: Name of the pass
        pass_data: Pass data dictionary
        console: Optional console instance
    """
    c = console or _get_console()

    c.print(f"\n[bold cyan]Pass: {pass_name}[/bold cyan]")

    if pass_data.get("evidence_summary"):
        evidence = pass_data["evidence_summary"]
        table = create_table(
            "Evidence Summary",
            [
                ("Metric", "cyan"),
                ("Value", "green"),
            ],
        )
        table.add_row("Changed Regions", str(evidence.get("changed_region_count", 0)))
        table.add_row("Structural Issues", str(evidence.get("structural_issue_count", 0)))
        table.add_row("Symbolic Mismatches", str(evidence.get("symbolic_binary_mismatched_regions", 0)))
        c.print(table)


def render_report_filter_messages(
    only_pass: str | None,
    resolved_only_pass: str | None,
    only_pass_failure: str | None,
    resolved_only_pass_failure: str | None,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    *,
    console: Console | None = None,
) -> None:
    """
    Render filter resolution messages.

    Args:
        only_pass: Original --only-pass argument
        resolved_only_pass: Resolved pass name
        only_pass_failure: Original --only-pass-failure argument
        resolved_only_pass_failure: Resolved pass failure name
        only_risky_passes: --only-risky-passes flag
        only_uncovered_passes: --only-uncovered-passes flag
        only_covered_passes: --only-covered-passes flag
        only_clean_passes: --only-clean-passes flag
        console: Optional console instance
    """
    c = console or _get_console()

    if only_pass is not None and resolved_only_pass != only_pass:
        c.print(f"[bold]Pass Filter Resolution[/bold]: {only_pass} -> {resolved_only_pass}")

    if only_pass_failure is not None and resolved_only_pass_failure != only_pass_failure:
        c.print(f"[bold]Pass Failure Filter Resolution[/bold]: {only_pass_failure} -> {resolved_only_pass_failure}")

    if only_risky_passes:
        c.print("[bold]Filter[/bold]: Showing only passes with symbolic mismatches or structural issues")

    if only_uncovered_passes:
        c.print("[bold]Filter[/bold]: Showing only clean passes without effective symbolic coverage")

    if only_covered_passes:
        c.print("[bold]Filter[/bold]: Showing only clean passes with effective symbolic coverage")

    if only_clean_passes:
        c.print("[bold]Filter[/bold]: Showing only passes with no structural issues and clean symbolic evidence")


def render_summary_table(
    summary: dict[str, Any],
    *,
    console: Console | None = None,
) -> None:
    """
    Render a generic summary table.

    Args:
        summary: Summary dictionary
        console: Optional console instance
    """
    c = console or _get_console()

    table = create_table(
        "Report Summary",
        [
            ("Metric", "cyan"),
            ("Value", "green"),
        ],
    )

    for key, value in summary.items():
        if isinstance(value, dict):
            continue
        if isinstance(value, list):
            continue
        table.add_row(key.replace("_", " ").title(), str(value))

    c.print(table)


def render_gate_evaluation_sections(
    gate_evaluation: dict[str, Any],
    gate_requested: dict[str, Any],
    gate_results: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render persisted gate evaluation and failure sections.

    Args:
        gate_evaluation: Gate evaluation dict
        gate_requested: Gate requested dict
        gate_results: Gate results dict
        gate_failure_summary: Gate failure summary dict
        gate_failure_priority: Priority ordered gate failures
        gate_failure_severity_priority: Severity priority ordered failures
        console: Optional console instance
    """
    c = console or _get_console()

    if not gate_evaluation:
        return

    c.print("[bold]Gate Evaluation[/bold]: " f"all_passed={'yes' if gate_results.get('all_passed', True) else 'no'}")

    if gate_requested.get("min_severity") is not None:
        c.print(
            "  "
            f"min_severity={gate_requested.get('min_severity')}, "
            f"passed={'yes' if gate_results.get('min_severity_passed', True) else 'no'}"
        )

    if gate_requested.get("require_pass_severity"):
        requested_rules = ", ".join(
            f"{item.get('pass_name')}<={item.get('max_severity')}"
            for item in gate_requested.get("require_pass_severity", [])
        )
        c.print(
            "  "
            f"require_pass_severity={requested_rules}, "
            f"passed={'yes' if gate_results.get('require_pass_severity_passed', True) else 'no'}"
        )
        failures = list(gate_results.get("require_pass_severity_failures", []))
        if failures:
            c.print("  failures: " + ", ".join(failures))

    c.print(
        "[bold]Gate Failure Summary[/bold]: "
        f"min_severity_failed={'yes' if gate_failure_summary.get('min_severity_failed') else 'no'}, "
        f"require_pass_failures={gate_failure_summary.get('require_pass_severity_failure_count', 0)}"
    )

    severity_counts = gate_failure_summary.get("require_pass_severity_failures_by_expected_severity", {})
    if severity_counts:
        c.print(
            "  expected_severity_counts="
            + ", ".join(f"{severity}:{count}" for severity, count in severity_counts.items())
        )

    if gate_failure_severity_priority:
        c.print(
            "  expected_severity_priority="
            + ", ".join(f"{row.get('severity')}:{row.get('failure_count')}" for row in gate_failure_severity_priority)
        )

    pass_failure_map = gate_failure_summary.get("require_pass_severity_failures_by_pass", {})
    if pass_failure_map:
        c.print("[bold]Gate Failure By Pass[/bold]:")
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
            failures_list = list(row.get("failures", []))
            failure_count = row.get("failure_count", len(failures_list))
            strictest = row.get("strictest_expected_severity", "unknown")
            c.print(
                f"  [yellow]{pass_name}[/yellow] "
                f"(count={failure_count}, strictest_expected={strictest}): " + ", ".join(failures_list)
            )


def render_general_report_sections(
    filtered_summary: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    degraded_passes: list[dict[str, Any]],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    validation_policy: dict[str, Any] | None,
    gate_evaluation: dict[str, Any],
    gate_requested: dict[str, Any],
    gate_results: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    resolved_only_pass: str | None,
    *,
    console: Console | None = None,
) -> None:
    """
    Render general report flow sections.

    Args:
        filtered_summary: Filtered summary dict
        summary: Full summary dict
        pass_results: Pass results dict
        degraded_passes: List of degraded passes
        requested_validation_mode: Requested validation mode
        effective_validation_mode: Effective validation mode
        degraded_validation: Whether validation was degraded
        validation_policy: Validation policy dict
        gate_evaluation: Gate evaluation dict
        gate_requested: Gate requested dict
        gate_results: Gate results dict
        gate_failure_summary: Gate failure summary dict
        gate_failure_priority: Priority ordered gate failures
        gate_failure_severity_priority: Severity priority ordered failures
        degradation_roles: Degradation roles dict
        resolved_only_pass: Resolved only pass filter
        console: Optional console instance
    """
    c = console or _get_console()

    if resolved_only_pass:
        c.print(f"\n[bold cyan]Filtered to Pass: {resolved_only_pass}[/bold cyan]")

    if degraded_validation:
        c.print(
            f"\n[yellow]Validation Mode Degraded:[/yellow] "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )

    if gate_evaluation:
        render_gate_evaluation_sections(
            gate_evaluation=gate_evaluation,
            gate_requested=gate_requested,
            gate_results=gate_results,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            console=c,
        )

    if degradation_roles:
        render_degradation_sections(
            {"degraded_validation": degraded_validation, "roles": degradation_roles},
            console=c,
        )


def render_general_only_pass_sections(
    pass_name: str,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    resolved_only_pass: str | None,
    *,
    console: Console | None = None,
) -> None:
    """
    Render only-pass sections for general report.

    Args:
        pass_name: Pass name
        summary: Summary dict
        pass_results: Pass results dict
        resolved_only_pass: Resolved only pass filter
        console: Optional console instance
    """
    c = console or _get_console()

    if not resolved_only_pass:
        return

    c.print(f"\n[bold cyan]Single Pass Report: {pass_name}[/bold cyan]")

    pass_result = pass_results.get(pass_name, {})
    if pass_result:
        evidence = pass_result.get("evidence_summary", {})
        if evidence:
            render_only_pass_sections(pass_name, {"evidence_summary": evidence}, console=c)


def render_mismatch_summary_sections(
    mismatch_counts_by_pass: dict[str, int],
    mismatch_observables_by_pass: dict[str, list[str]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render mismatch summary sections.

    Args:
        mismatch_counts_by_pass: Dict of pass name to mismatch count
        mismatch_observables_by_pass: Dict of pass name to observable list
        console: Optional console instance
    """
    c = console or _get_console()

    if not mismatch_counts_by_pass:
        return

    table = create_table(
        "Observable Mismatches Summary",
        [
            ("Pass", "cyan"),
            ("Count", "red"),
            ("Observables", "yellow"),
        ],
    )

    for pass_name, count in sorted(mismatch_counts_by_pass.items(), key=lambda x: -x[1]):
        observables = mismatch_observables_by_pass.get(pass_name, [])[:3]
        obs_str = ", ".join(observables)
        if len(mismatch_observables_by_pass.get(pass_name, [])) > 3:
            obs_str += "..."
        table.add_row(pass_name, str(count), obs_str)

    c.print(table)


def render_validation_context_table(
    validation_contexts: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render validation context table.

    Args:
        validation_contexts: List of validation context dicts
        console: Optional console instance
    """
    if not validation_contexts:
        return

    c = console or _get_console()
    table = create_table(
        "Validation Context",
        [
            ("Pass", "cyan"),
            ("Mode", "blue"),
            ("Degraded", "yellow"),
        ],
    )

    for ctx in validation_contexts:
        table.add_row(
            ctx.get("pass_name", "unknown"),
            ctx.get("validation_mode", "unknown"),
            "Yes" if ctx.get("degraded_execution") else "No",
        )

    c.print(table)
