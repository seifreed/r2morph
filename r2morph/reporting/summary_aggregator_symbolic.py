"""Symbolic aggregation helpers for report summaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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
