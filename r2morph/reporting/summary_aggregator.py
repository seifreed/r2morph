"""
Summary and evidence aggregation logic extracted from cli.py and engine.py.

This module handles symbolic coverage summarization, evidence aggregation,
and pass result normalization.
"""

from dataclasses import dataclass
from typing import Any

from r2morph.reporting.gate_evaluator import ROLLBACK_SEVERITY_ORDER


@dataclass
class SymbolicStats:
    """Aggregated symbolic validation statistics."""

    symbolic_requested: int = 0
    observable_match: int = 0
    observable_mismatch: int = 0
    bounded_only: int = 0
    without_coverage: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "symbolic_requested": self.symbolic_requested,
            "observable_match": self.observable_match,
            "observable_mismatch": self.observable_mismatch,
            "bounded_only": self.bounded_only,
            "without_coverage": self.without_coverage,
        }


class SymbolicAggregator:
    """Aggregates symbolic validation statistics from mutation records."""

    @staticmethod
    def summarize_from_mutations(
        mutations: list[dict[str, Any]],
    ) -> tuple[dict[str, int], list[dict[str, Any]], dict[str, dict[str, int]]]:
        """Build global and per-pass symbolic status summaries."""
        global_counts: dict[str, int] = {}
        by_pass: dict[str, dict[str, int]] = {}

        for mutation in mutations:
            status = mutation.get("metadata", {}).get("symbolic_status")
            if not status:
                continue
            status = str(status)
            global_counts[status] = global_counts.get(status, 0) + 1
            pass_name = str(mutation.get("pass_name", "unknown"))
            pass_counts = by_pass.setdefault(pass_name, {})
            pass_counts[status] = pass_counts.get(status, 0) + 1

        rows: list[dict[str, Any]] = [
            {
                "pass_name": pass_name,
                "statuses": dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))),
            }
            for pass_name, counts in by_pass.items()
        ]
        rows.sort(
            key=lambda item: (
                -sum(dict(item["statuses"]).values()),
                item["pass_name"],
            )
        )

        return (
            dict(sorted(global_counts.items(), key=lambda item: (-item[1], item[0]))),
            rows,
            {str(row["pass_name"]): dict(row["statuses"]) for row in rows},
        )

    @staticmethod
    def summarize_coverage_by_pass(
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Aggregate symbolic coverage outcomes by pass for machine-readable reports."""
        by_pass: dict[str, dict[str, int]] = {}

        for mutation in mutations:
            metadata = mutation.get("metadata", {})
            if not metadata.get("symbolic_requested"):
                continue
            pass_name = mutation.get("pass_name", "unknown")
            stats = by_pass.setdefault(
                pass_name,
                {
                    "symbolic_requested": 0,
                    "observable_match": 0,
                    "observable_mismatch": 0,
                    "bounded_only": 0,
                    "without_coverage": 0,
                },
            )
            stats["symbolic_requested"] += 1
            if metadata.get("symbolic_observable_check_performed"):
                if metadata.get("symbolic_observable_equivalent", False):
                    stats["observable_match"] += 1
                else:
                    stats["observable_mismatch"] += 1
            elif metadata.get("symbolic_status") in {
                "bounded-step-passed",
                "bounded-step-known-equivalence",
                "bounded-step-observables-match",
                "bounded-step-observable-mismatch",
            }:
                stats["bounded_only"] += 1
            else:
                stats["without_coverage"] += 1

        rows: list[dict[str, Any]] = []
        for pass_name, stats in by_pass.items():
            rows.append({"pass_name": pass_name, **stats})
        rows.sort(
            key=lambda item: (
                -int(item["symbolic_requested"]),
                -int(item["observable_match"]),
                -int(item["observable_mismatch"]),
                item["pass_name"],
            )
        )
        return rows

    @staticmethod
    def summarize_issue_passes(
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Aggregate symbolic issue counts by pass for machine-readable reports."""
        by_pass: dict[str, dict[str, int]] = {}

        for mutation in mutations:
            metadata = mutation.get("metadata", {})
            if not metadata.get("symbolic_requested"):
                continue
            pass_name = mutation.get("pass_name", "unknown")
            stats = by_pass.setdefault(
                pass_name,
                {
                    "observable_mismatch": 0,
                    "without_coverage": 0,
                    "bounded_only": 0,
                },
            )
            if metadata.get("symbolic_observable_check_performed"):
                if not metadata.get("symbolic_observable_equivalent", False):
                    stats["observable_mismatch"] += 1
            elif metadata.get("symbolic_status") in {
                "bounded-step-passed",
                "bounded-step-known-equivalence",
                "bounded-step-observables-match",
                "bounded-step-observable-mismatch",
            }:
                stats["bounded_only"] += 1
            else:
                stats["without_coverage"] += 1

        issue_rows: list[dict[str, Any]] = []
        for pass_name, stats in by_pass.items():
            if stats["observable_mismatch"] == 0 and stats["without_coverage"] == 0 and stats["bounded_only"] == 0:
                continue
            severity = (
                "mismatch"
                if stats["observable_mismatch"] > 0
                else "without-coverage" if stats["without_coverage"] > 0 else "bounded-only"
            )
            issue_rows.append(
                {
                    "pass_name": pass_name,
                    "severity": severity,
                    "observable_mismatch": stats["observable_mismatch"],
                    "without_coverage": stats["without_coverage"],
                    "bounded_only": stats["bounded_only"],
                }
            )
        issue_rows.sort(
            key=lambda item: (
                -int(item["observable_mismatch"]),
                -int(item["without_coverage"]),
                -int(item["bounded_only"]),
                item["pass_name"],
            )
        )
        return issue_rows

    @staticmethod
    def summarize_observable_mismatches_by_pass(
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Aggregate observable symbolic mismatches by pass for report triage."""
        counts: dict[str, dict[str, Any]] = {}

        for mutation in mutations:
            metadata = mutation.get("metadata", {})
            if not metadata.get("symbolic_observable_check_performed"):
                continue
            if metadata.get("symbolic_observable_equivalent", False):
                continue
            pass_name = mutation.get("pass_name", "unknown")
            row = counts.setdefault(
                pass_name,
                {
                    "pass_name": pass_name,
                    "mismatch_count": 0,
                    "observables": set(),
                },
            )
            row["mismatch_count"] += 1
            row["observables"].update(metadata.get("symbolic_observable_mismatches", []))

        rows = [
            {
                "pass_name": row["pass_name"],
                "mismatch_count": row["mismatch_count"],
                "observables": sorted(row["observables"]),
            }
            for row in counts.values()
        ]
        rows.sort(key=lambda item: (-item["mismatch_count"], item["pass_name"]))
        return rows


class EvidenceAggregator:
    """Aggregates evidence summaries from pass results."""

    @staticmethod
    def summarize_structural_evidence(
        structural_regions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build a compact structural-evidence digest from region-level findings."""
        validators: set[str] = set()
        severities: dict[str, int] = {}
        messages: list[str] = []

        for region in structural_regions:
            validators.update(region.get("validators", []))
            for severity in region.get("severities", []):
                severities[severity] = severities.get(severity, 0) + 1
            messages.extend(str(message) for message in region.get("messages", []))

        unique_messages = sorted({message for message in messages if message})
        return {
            "region_count": len(structural_regions),
            "validators": sorted(validators),
            "severity_counts": {
                key: severities[key] for key in sorted(severities, key=lambda item: (-severities[item], item))
            },
            "sample_messages": unique_messages[:5],
        }

    @staticmethod
    def build_for_pass(
        pass_name: str,
        pass_result: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a compact structural/symbolic evidence summary for one pass."""
        diff_summary = pass_result.get("diff_summary", {})
        mutations = list(pass_result.get("mutations", []))
        control_flow_observables: set[str] = set()
        symbolic_regions = []
        matched_regions = 0
        mismatched_regions = 0
        max_original_trace_len = 0
        max_mutated_trace_len = 0
        memory_write_activity = 0

        for mutation in mutations:
            metadata = mutation.get("metadata", {})
            if not metadata.get("symbolic_binary_check_performed"):
                continue
            mismatches = list(metadata.get("symbolic_binary_mismatches", []))
            if mismatches:
                mismatched_regions += 1
            else:
                matched_regions += 1
            control_flow_observables.update(metadata.get("symbolic_binary_control_flow_observables", []))
            max_original_trace_len = max(
                max_original_trace_len,
                len(metadata.get("symbolic_binary_original_trace_addresses", [])),
            )
            max_mutated_trace_len = max(
                max_mutated_trace_len,
                len(metadata.get("symbolic_binary_mutated_trace_addresses", [])),
            )
            memory_write_activity += int(metadata.get("symbolic_binary_original_memory_write_count", 0))
            memory_write_activity += int(metadata.get("symbolic_binary_mutated_memory_write_count", 0))
            symbolic_regions.append(
                {
                    "start_address": mutation.get("start_address"),
                    "end_address": mutation.get("end_address"),
                    "equivalent": bool(metadata.get("symbolic_binary_equivalent", False)),
                    "mismatches": mismatches,
                    "mismatch_count": len(mismatches),
                    "step_strategy": metadata.get("symbolic_binary_step_strategy"),
                    "original_region_exit_address": metadata.get("symbolic_binary_original_region_exit_address"),
                    "mutated_region_exit_address": metadata.get("symbolic_binary_mutated_region_exit_address"),
                    "original_trace_length": len(metadata.get("symbolic_binary_original_trace_addresses", [])),
                    "mutated_trace_length": len(metadata.get("symbolic_binary_mutated_trace_addresses", [])),
                    "original_region_exit_steps": metadata.get("symbolic_binary_original_region_exit_steps", 0),
                    "mutated_region_exit_steps": metadata.get("symbolic_binary_mutated_region_exit_steps", 0),
                }
            )

        symbolic_regions.sort(
            key=lambda item: (
                len(item["mismatches"]) == 0,
                -(item["mutated_region_exit_steps"] + item["original_region_exit_steps"]),
                item["start_address"] or 0,
            )
        )

        return {
            "pass_name": pass_name,
            "changed_region_count": len(diff_summary.get("changed_regions", [])),
            "changed_bytes": int(diff_summary.get("changed_bytes", 0)),
            "structural_issue_count": int(diff_summary.get("structural_issue_count", 0)),
            "structural_region_count": len(diff_summary.get("structural_regions", [])),
            "symbolic_binary_regions_checked": matched_regions + mismatched_regions,
            "symbolic_binary_matched_regions": matched_regions,
            "symbolic_binary_mismatched_regions": mismatched_regions,
            "control_flow_observables": sorted(control_flow_observables),
            "max_original_trace_length": max_original_trace_len,
            "max_mutated_trace_length": max_mutated_trace_len,
            "memory_write_activity": memory_write_activity,
            "region_exit_match_count": sum(
                1
                for row in symbolic_regions
                if row.get("original_region_exit_address") == row.get("mutated_region_exit_address")
                and row.get("original_region_exit_address") is not None
            ),
            "symbolic_regions": symbolic_regions,
            "rolled_back": bool(pass_result.get("rolled_back", False)),
            "status": pass_result.get("status", "unknown"),
        }

    @staticmethod
    def summarize_pass_evidence(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Aggregate per-pass evidence summaries for tooling."""
        rows = []
        for pass_name, pass_result in pass_results.items():
            evidence_summary = pass_result.get("evidence_summary", {})
            rows.append(
                {
                    "pass_name": pass_name,
                    "changed_region_count": evidence_summary.get("changed_region_count", 0),
                    "structural_issue_count": evidence_summary.get("structural_issue_count", 0),
                    "symbolic_binary_regions_checked": evidence_summary.get("symbolic_binary_regions_checked", 0),
                    "symbolic_binary_mismatched_regions": evidence_summary.get("symbolic_binary_mismatched_regions", 0),
                    "rolled_back": evidence_summary.get("rolled_back", False),
                    "status": evidence_summary.get("status", "unknown"),
                }
            )
        rows.sort(
            key=lambda item: (
                -item["symbolic_binary_mismatched_regions"],
                -item["structural_issue_count"],
                -item["changed_region_count"],
                item["pass_name"],
            )
        )
        return rows


class SummaryAggregator:
    """Aggregates summaries across all passes for report generation."""

    @staticmethod
    def summarize_degradation_roles(
        pass_results: dict[str, Any],
    ) -> dict[str, int]:
        """Aggregate degradation role counts across pass validation contexts."""
        counts: dict[str, int] = {}
        for pass_result in pass_results.values():
            role = pass_result.get("validation_context", {}).get("role")
            if not role:
                continue
            counts[role] = counts.get(role, 0) + 1
        return counts

    @staticmethod
    def summarize_diff_digest(pass_results: dict[str, Any]) -> dict[str, Any]:
        """Build a compact diff digest across passes."""
        digest: dict[str, Any] = {
            "changed_region_count": 0,
            "changed_bytes": 0,
            "mutation_kinds": [],
            "passes_with_changes": [],
        }
        mutation_kinds: set[str] = set()
        passes_with_changes: list[dict[str, Any]] = []

        for pass_name, pass_result in pass_results.items():
            diff_summary = pass_result.get("diff_summary", {})
            changed_regions = list(diff_summary.get("changed_regions", []))
            changed_bytes = int(diff_summary.get("changed_bytes", 0))
            digest["changed_region_count"] = int(digest["changed_region_count"]) + len(changed_regions)
            digest["changed_bytes"] = int(digest["changed_bytes"]) + changed_bytes
            mutation_kinds.update(diff_summary.get("mutation_kinds", []))
            if changed_regions or changed_bytes:
                passes_with_changes.append(
                    {
                        "pass_name": pass_name,
                        "changed_region_count": len(changed_regions),
                        "changed_bytes": changed_bytes,
                    }
                )

        passes_with_changes.sort(
            key=lambda item: (
                -item["changed_bytes"],
                -item["changed_region_count"],
                item["pass_name"],
            )
        )
        digest["mutation_kinds"] = sorted(mutation_kinds)
        digest["passes_with_changes"] = passes_with_changes
        return digest

    @staticmethod
    def summarize_pass_timings(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Build a compact per-pass timing summary for tooling."""
        rows: list[dict[str, Any]] = []
        for pass_name, pass_result in pass_results.items():
            validation = pass_result.get("validation", {})
            rows.append(
                {
                    "pass_name": pass_name,
                    "execution_time_seconds": round(float(pass_result.get("execution_time_seconds", 0.0)), 6),
                    "mutations": len(pass_result.get("mutations", [])),
                    "rolled_back": bool(pass_result.get("rolled_back", False)),
                    "validation_issue_count": len(validation.get("issues", [])),
                }
            )
        rows.sort(key=lambda item: (-float(item["execution_time_seconds"]), item["pass_name"]))
        return rows

    @staticmethod
    def summarize_discarded_mutations(
        discarded_mutations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Aggregate discarded mutations by pass and reason."""
        severity_by_reason = {
            "runtime_validation_failed": "high",
            "structural_validation_failed": "high",
            "symbolic_validation_failed": "high",
            "validation_failed": "high",
            "rollback": "medium",
            "skip_invalid_pass": "medium",
            "skip_invalid_mutation": "low",
            "unknown": "low",
        }
        severity_order = ROLLBACK_SEVERITY_ORDER
        by_pass: dict[str, int] = {}
        by_reason: dict[str, int] = {}
        by_pass_reason: dict[str, dict[str, int]] = {}

        for mutation in discarded_mutations:
            pass_name = str(mutation.get("pass_name", "unknown"))
            reason = str(mutation.get("discard_reason", "unknown"))
            by_pass[pass_name] = by_pass.get(pass_name, 0) + 1
            by_reason[reason] = by_reason.get(reason, 0) + 1
            pass_reason = by_pass_reason.setdefault(pass_name, {})
            pass_reason[reason] = pass_reason.get(reason, 0) + 1

        rows: list[dict[str, Any]] = [
            {
                "pass_name": pass_name,
                "discarded_count": count,
                "impact_severity": min(
                    (severity_by_reason.get(reason, "low") for reason in by_pass_reason.get(pass_name, {})),
                    key=lambda severity: severity_order.get(severity, 99),
                    default="low",
                ),
                "reasons": dict(
                    sorted(
                        by_pass_reason.get(pass_name, {}).items(),
                        key=lambda item: (-item[1], item[0]),
                    )
                ),
            }
            for pass_name, count in by_pass.items()
        ]
        rows.sort(
            key=lambda item: (
                severity_order.get(str(item.get("impact_severity", "low")), 99),
                -int(item["discarded_count"]),
                item["pass_name"],
            )
        )
        return {
            "by_pass": rows,
            "by_reason": dict(sorted(by_reason.items(), key=lambda item: (-item[1], item[0]))),
            "by_impact": {
                severity: [dict(row) for row in rows if row.get("impact_severity") == severity]
                for severity in ("high", "medium", "low")
            },
            "by_pass_map": {
                row["pass_name"]: {
                    "discarded_count": row["discarded_count"],
                    "impact_severity": row.get("impact_severity", "low"),
                    "reasons": dict(row["reasons"]),
                }
                for row in rows
            },
        }
