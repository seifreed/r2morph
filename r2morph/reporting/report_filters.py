"""
Report filtering logic extracted from cli.py.

This module handles pass filtering, risk bucket resolution,
and mismatch view resolution for reports.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class PassFilterSets:
    """Resolved pass filter sets for report filtering."""

    risky: set[str]
    structural: set[str]
    symbolic: set[str]
    clean: set[str]
    covered: set[str]
    uncovered: set[str]

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "risky": sorted(self.risky),
            "structural": sorted(self.structural),
            "symbolic": sorted(self.symbolic),
            "clean": sorted(self.clean),
            "covered": sorted(self.covered),
            "uncovered": sorted(self.uncovered),
        }


class PassFilterResolver:
    """Resolves pass filter buckets from persisted summary first, then fall back."""

    @staticmethod
    def resolve(
        summary: dict[str, Any],
        pass_results: dict[str, Any],
    ) -> dict[str, set[str]]:
        """Resolve pass filter buckets from persisted summary first, then fall back."""
        report_views = dict(summary.get("report_views", {}) or {})
        general_renderer_state = dict(report_views.get("general_renderer_state", {}) or {})
        pass_filter_views = dict(
            report_views.get("general_filter_views", report_views.get("pass_filter_views", {}))
            or {}
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

        risk_buckets = dict(
            PassFilterResolver._summary_first(
                summary,
                "pass_risk_buckets",
                pass_filter_views or report_views.get("passes", {}),
            )
            or {}
        )
        coverage_buckets = dict(
            PassFilterResolver._summary_first(
                summary,
                "pass_coverage_buckets",
                {
                    "covered": (pass_filter_views or report_views.get("passes", {})).get(
                        "covered", []
                    ),
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
            PassFilterResolver._summary_first(
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
                    resolved[kind] = PassFilterResolver._pass_names_from_triage_rows(
                        triage_rows, kind=kind
                    )

        summary_pass_evidence = list(
            PassFilterResolver._summary_first(summary, "pass_evidence", [])
        )
        fallback_checks = {
            "risky": PassFilterResolver._is_risky_pass,
            "structural": PassFilterResolver._has_structural_risk,
            "symbolic": PassFilterResolver._has_symbolic_risk,
            "clean": PassFilterResolver._is_clean_pass,
            "covered": PassFilterResolver._is_covered_pass,
            "uncovered": PassFilterResolver._is_uncovered_pass,
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
                    pass_name = str(row.get("pass_name", ""))
                    if pass_name and predicate(
                        row,
                        pass_results.get(pass_name, {}).get("symbolic_summary"),
                    ):
                        matches.add(pass_name)
            resolved[kind] = matches

        return resolved

    @staticmethod
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

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def _has_structural_risk(
        evidence: dict[str, Any] | None, symbolic: dict[str, Any] | None
    ) -> bool:
        e = evidence or {}
        return int(e.get("structural_issue_count", 0)) > 0

    @staticmethod
    def _has_symbolic_risk(
        evidence: dict[str, Any] | None, symbolic: dict[str, Any] | None
    ) -> bool:
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

    @staticmethod
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

    @staticmethod
    def _is_covered_pass(evidence: dict[str, Any] | None, symbolic: dict[str, Any] | None) -> bool:
        e = evidence or {}
        s = symbolic or {}
        symbolic_requested = int(s.get("symbolic_requested", 0))
        without_coverage = int(s.get("without_coverage", 0))
        checked_regions = int(e.get("symbolic_binary_regions_checked", 0))
        return (
            PassFilterResolver._is_clean_pass(evidence, symbolic)
            and symbolic_requested > 0
            and without_coverage == 0
            and checked_regions > 0
        )

    @staticmethod
    def _is_uncovered_pass(
        evidence: dict[str, Any] | None, symbolic: dict[str, Any] | None
    ) -> bool:
        return PassFilterResolver._is_clean_pass(
            evidence, symbolic
        ) and not PassFilterResolver._is_covered_pass(evidence, symbolic)


class ReportFilters:
    """Handles report mutation and view filtering."""

    @staticmethod
    def select_report_mutations(
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
        """Select mutations for report based on active filters."""
        filtered = []
        adjusted_degraded_passes = list(degraded_passes)

        for mutation in all_mutations:
            pass_name = mutation.get("pass_name", "unknown")
            metadata = mutation.get("metadata", {})

            if resolved_only_pass and pass_name != resolved_only_pass:
                continue

            if only_status and metadata.get("symbolic_status") != only_status:
                continue

            if only_degraded:
                degraded = metadata.get("degraded_execution", False)
                triggered = metadata.get("degradation_triggered_by_pass", False)
                if not (degraded or triggered):
                    continue

            if only_risky_filters and pass_name not in selected_risk_pass_names:
                continue

            filtered.append(mutation)

        if only_degraded and adjusted_degraded_passes:
            adjusted_degraded_passes = [
                item
                for item in adjusted_degraded_passes
                if item.get("pass_name", item.get("mutation", "unknown"))
                in {m.get("pass_name", "unknown") for m in filtered}
            ]

        return filtered, adjusted_degraded_passes

    @staticmethod
    def resolve_mismatch_view(
        summary: dict[str, Any],
        mutations: list[dict[str, Any]],
    ) -> tuple[dict[str, int], dict[str, list[str]], list[dict[str, Any]]]:
        """Resolve mismatch counts/observables/priority from persisted summary first."""
        report_views = dict(summary.get("report_views", {}) or {})
        only_mismatches_view = dict(report_views.get("only_mismatches", {}) or {})
        mismatch_map = dict(
            ReportFilters._summary_first(
                summary,
                "observable_mismatch_map",
                only_mismatches_view.get("by_pass", report_views.get("mismatch_map", {})),
            )
            or {}
        )
        mismatch_priority = list(
            ReportFilters._summary_first(
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
                pass_name: int(row.get("mismatch_count", 0))
                for pass_name, row in mismatch_map.items()
            }
            observables_by_pass = {
                pass_name: list(row.get("observables", []))
                for pass_name, row in mismatch_map.items()
            }
        else:
            persisted_rows = list(
                ReportFilters._summary_first(summary, "observable_mismatch_by_pass", [])
            )
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

    @staticmethod
    def _summary_first(summary: dict[str, Any], key: str, fallback: Any) -> Any:
        """Return a persisted summary value when present, otherwise the fallback."""
        value = summary.get(key)
        if value is None:
            return fallback
        if isinstance(value, (list, dict)) and not value:
            return fallback
        return value
