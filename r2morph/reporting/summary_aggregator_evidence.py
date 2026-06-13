"""Evidence aggregation helpers for report summaries."""

from __future__ import annotations

from typing import Any


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
