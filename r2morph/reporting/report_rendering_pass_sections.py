"""Pass-focused report rendering helpers."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_rendering_primitives import _get_console


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
