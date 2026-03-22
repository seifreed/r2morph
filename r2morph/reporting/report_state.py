"""
Report state resolution functions extracted from cli.py.

This module handles resolution of report state including:
- General report flow state
- Symbolic state resolution
- Pass filter resolution
- Mismatch view resolution
"""

from typing import Any


def _normalized_pass_map(normalized_results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build a normalized pass map from results."""
    return {
        str(row.get("pass_name", "")): dict(row)
        for row in normalized_results
        if row.get("pass_name")
    }


def resolve_general_symbolic_state(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
    pass_results: dict[str, Any],
    summarize_symbolic_func: callable,
    render_symbolic_func: callable,
) -> dict[str, Any]:
    """
    Resolve symbolic summary inputs for the general report path.

    Args:
        summary: Report summary dict
        mutations: List of mutations
        pass_results: Pass results dict
        summarize_symbolic_func: Function to summarize symbolic view
        render_symbolic_func: Function to render symbolic sections

    Returns:
        Dict with symbolic state
    """
    (
        symbolic_requested,
        observable_match,
        observable_mismatch,
        bounded_only,
        observable_not_run,
        by_pass,
        mismatch_rows,
    ) = summarize_symbolic_func(summary=summary, mutations=mutations)

    render_symbolic_func(
        symbolic_requested=symbolic_requested,
        observable_match=observable_match,
        observable_mismatch=observable_mismatch,
        bounded_only=bounded_only,
        observable_not_run=observable_not_run,
        summary=summary,
        pass_results=pass_results,
        by_pass=by_pass,
        mismatch_rows=mismatch_rows,
    )

    summary_normalized_pass_results = list(summary.get("normalized_pass_results", []) or [])
    return {
        "symbolic_requested": symbolic_requested,
        "observable_match": observable_match,
        "observable_mismatch": observable_mismatch,
        "bounded_only": bounded_only,
        "observable_not_run": observable_not_run,
        "by_pass": by_pass,
        "summary_normalized_pass_results": summary_normalized_pass_results,
        "normalized_pass_map": _normalized_pass_map(summary_normalized_pass_results),
    }


def resolve_mismatch_view(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
) -> tuple[dict[str, int], dict[str, list[str]], list[dict[str, Any]]]:
    """
    Resolve mismatch counts/observables/priority from persisted summary first.

    Args:
        summary: Report summary dict
        mutations: List of mutations

    Returns:
        Tuple of (counts_by_pass, observables_by_pass, mismatch_priority)
    """
    report_views = dict(summary.get("report_views", {}) or {})
    only_mismatches_view = dict(report_views.get("only_mismatches", {}) or {})
    mismatch_map = dict(
        _summary_first(
            summary,
            "observable_mismatch_map",
            only_mismatches_view.get("by_pass", report_views.get("mismatch_map", {})),
        )
        or {}
    )
    mismatch_priority = list(
        _summary_first(
            summary,
            "observable_mismatch_priority",
            only_mismatches_view.get("priority", report_views.get("mismatch_priority", [])),
        )
        or []
    )
    mismatch_view = list(
        only_mismatches_view.get("rows", report_views.get("mismatch_view", [])) or []
    )
    mismatch_compact_rows = list(only_mismatches_view.get("compact_rows", []) or [])

    if mismatch_map:
        counts_by_pass = {
            pass_name: int(row.get("mismatch_count", 0)) for pass_name, row in mismatch_map.items()
        }
        observables_by_pass = {
            pass_name: list(row.get("observables", [])) for pass_name, row in mismatch_map.items()
        }
    else:
        persisted_rows = list(_summary_first(summary, "observable_mismatch_by_pass", []))
        counts_by_pass = {
            row.get("pass_name", "unknown"): int(row.get("mismatch_count", 0))
            for row in persisted_rows
            if row.get("pass_name")
        }
        observables_by_pass = {
            row.get("pass_name", "unknown"): list(row.get("observables", []))
            for row in persisted_rows
            if row.get("pass_name")
        }
        if not counts_by_pass and mismatch_compact_rows:
            counts_by_pass = {
                str(row.get("pass_name")): int(row.get("mismatch_count", 0))
                for row in mismatch_compact_rows
                if row.get("pass_name")
            }
        if not observables_by_pass and mismatch_view:
            observables_by_pass = {
                str(row.get("pass_name")): list(row.get("observables", []))
                for row in mismatch_view
                if row.get("pass_name")
            }

    for mutation in mutations:
        pass_name = mutation.get("pass_name", "unknown")
        counts_by_pass[pass_name] = counts_by_pass.get(pass_name, 0) + 1
        mismatch_observables = mutation.get("metadata", {}).get(
            "symbolic_observable_mismatches", []
        )
        if mismatch_observables:
            merged = set(observables_by_pass.get(pass_name, []))
            merged.update(mismatch_observables)
            observables_by_pass[pass_name] = sorted(merged)

    return counts_by_pass, observables_by_pass, mismatch_priority or mismatch_view


def _summary_first(summary: dict[str, Any], key: str, fallback: Any) -> Any:
    """Return a persisted summary value when present, otherwise the fallback."""
    value = summary.get(key)
    if value is None:
        return fallback
    if isinstance(value, (list, dict)) and not value:
        return fallback
    return value


def resolve_pass_filter_sets(
    *,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    summary_first_func: callable = None,
) -> dict[str, set[str]]:
    """
    Resolve pass filter buckets from persisted summary first, then fall back.

    Args:
        summary: Report summary dict
        pass_results: Pass results dict
        summary_first_func: Optional function for summary-first resolution

    Returns:
        Dict with filter sets: risky, structural, symbolic, clean, covered, uncovered
    """
    report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(report_views.get("general_renderer_state", {}) or {})
    pass_filter_views = dict(
        report_views.get("general_filter_views", report_views.get("pass_filter_views", {})) or {}
    )

    if not pass_filter_views and general_renderer_state.get("general_filter_views"):
        pass_filter_views = {
            f"only_{key}_passes"
            if key in {"risky", "clean", "covered", "uncovered"}
            else "only_structural_risk"
            if key == "structural_risk"
            else "only_symbolic_risk"
            if key == "symbolic_risk"
            else key: value
            for key, value in dict(
                general_renderer_state.get("general_filter_views", {}) or {}
            ).items()
        }

    if not pass_filter_views and general_renderer_state.get("filter_views"):
        pass_filter_views = {
            f"only_{key}_passes"
            if key in {"risky", "clean", "covered", "uncovered"}
            else "only_structural_risk"
            if key == "structural_risk"
            else "only_symbolic_risk"
            if key == "symbolic_risk"
            else key: value
            for key, value in dict(general_renderer_state.get("filter_views", {}) or {}).items()
        }

    risk_buckets = dict(_summary_first(summary, "pass_risk_buckets", {}) or {})
    coverage_buckets = dict(
        _summary_first(
            summary,
            "pass_coverage_buckets",
            {
                "covered": (pass_filter_views or report_views.get("passes", {})).get("covered", []),
                "uncovered": (pass_filter_views or report_views.get("passes", {})).get(
                    "uncovered", []
                ),
                "clean_only": (pass_filter_views or report_views.get("passes", {})).get(
                    "clean", []
                ),
            },
        )
        or {}
    )

    triage_rows = list(
        _summary_first(
            summary,
            "pass_triage_rows",
            report_views.get("general_triage_rows", report_views.get("triage_priority", [])),
        )
        or []
    )

    if not triage_rows and general_renderer_state.get("triage_rows"):
        triage_rows = list(general_renderer_state.get("triage_rows", []) or [])

    resolved = {
        "risky": set(pass_filter_views.get("only_risky_passes", risk_buckets.get("risky", []))),
        "structural": set(
            pass_filter_views.get(
                "only_structural_risk",
                risk_buckets.get("structural", []),
            )
        ),
        "symbolic": set(
            pass_filter_views.get("only_symbolic_risk", risk_buckets.get("symbolic", []))
        ),
        "clean": set(pass_filter_views.get("only_clean_passes", risk_buckets.get("clean", []))),
        "covered": set(
            pass_filter_views.get(
                "only_covered_passes",
                coverage_buckets.get("covered", []),
            )
        ),
        "uncovered": set(
            pass_filter_views.get(
                "only_uncovered_passes",
                coverage_buckets.get("uncovered", []),
            )
        ),
    }

    if triage_rows:
        for kind in ("risky", "structural", "symbolic", "clean", "covered", "uncovered"):
            if not resolved[kind]:
                resolved[kind] = _pass_names_from_triage_rows(triage_rows, kind=kind)

    summary_pass_evidence = list(_summary_first(summary, "pass_evidence", []))
    fallback_checks = {
        "risky": _is_risky_pass,
        "structural": _has_structural_risk,
        "symbolic": _has_symbolic_risk,
        "clean": _is_clean_pass,
        "covered": _is_covered_pass,
        "uncovered": _is_uncovered_pass,
    }

    for kind, predicate in fallback_checks.items():
        if resolved[kind]:
            continue
        matches = {
            pass_name
            for pass_name, pass_result in pass_results.items()
            if predicate(
                pass_result.get("evidence_summary"),
                pass_result.get("symbolic_summary"),
            )
        }
        if not matches and summary_pass_evidence:
            for row in summary_pass_evidence:
                pass_name_str = str(row.get("pass_name", ""))
                if pass_name_str and predicate(
                    row,
                    pass_results.get(pass_name_str, {}).get("symbolic_summary"),
                ):
                    matches.add(pass_name_str)
        resolved[kind] = matches

    return resolved


def _pass_names_from_triage_rows(
    triage_rows: list[dict[str, Any]],
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
            or severity in {"mismatch", "without-coverage", "bounded-only"}
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


def _is_risky_pass(evidence: dict[str, Any] | None, symbolic: dict[str, Any] | None) -> bool:
    e = evidence or {}
    s = symbolic or {}
    structural_issues = int(e.get("structural_issue_count", 0))
    symbolic_mismatch = int(e.get("symbolic_binary_mismatched_regions", 0))
    severity = str(s.get("severity", "not-requested"))
    issue_count = int(s.get("issue_count", 0))
    return (
        structural_issues > 0
        or symbolic_mismatch > 0
        or severity in {"mismatch", "without-coverage", "bounded-only"}
        or issue_count > 0
    )


def _has_structural_risk(evidence: dict[str, Any] | None, symbolic: dict[str, Any] | None) -> bool:
    e = evidence or {}
    return int(e.get("structural_issue_count", 0)) > 0


def _has_symbolic_risk(evidence: dict[str, Any] | None, symbolic: dict[str, Any] | None) -> bool:
    e = evidence or {}
    s = symbolic or {}
    symbolic_mismatch = int(e.get("symbolic_binary_mismatched_regions", 0))
    severity = str(s.get("severity", "not-requested"))
    issue_count = int(s.get("issue_count", 0))
    return (
        symbolic_mismatch > 0
        or severity in {"mismatch", "without-coverage", "bounded-only"}
        or issue_count > 0
    )


def _is_clean_pass(evidence: dict[str, Any] | None, symbolic: dict[str, Any] | None) -> bool:
    e = evidence or {}
    s = symbolic or {}
    structural_issues = int(e.get("structural_issue_count", 0))
    symbolic_mismatch = int(e.get("symbolic_binary_mismatched_regions", 0))
    severity = str(s.get("severity", "not-requested"))
    issue_count = int(s.get("issue_count", 0))
    return (
        structural_issues == 0
        and symbolic_mismatch == 0
        and severity in {"clean", "not-requested"}
        and issue_count == 0
    )


def _is_covered_pass(evidence: dict[str, Any] | None, symbolic: dict[str, Any] | None) -> bool:
    e = evidence or {}
    s = symbolic or {}
    symbolic_requested = int(s.get("symbolic_requested", 0))
    without_coverage = int(s.get("without_coverage", 0))
    checked_regions = int(e.get("symbolic_binary_regions_checked", 0))
    return (
        _is_clean_pass(evidence, symbolic)
        and symbolic_requested > 0
        and without_coverage == 0
        and checked_regions > 0
    )


def _is_uncovered_pass(evidence: dict[str, Any] | None, symbolic: dict[str, Any] | None) -> bool:
    return _is_clean_pass(evidence, symbolic) and not _is_covered_pass(evidence, symbolic)
