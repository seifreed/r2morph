"""Evidence and triage report helpers extracted from core.report_helpers."""

from __future__ import annotations

from typing import Any

from r2morph.core.report_helpers_discarded import (
    _build_discarded_mutation_priority as _build_discarded_mutation_priority,
)
from r2morph.core.report_helpers_discarded import (
    _summarize_discarded_mutations as _summarize_discarded_mutations,
)
from r2morph.core.report_helpers_evidence_summary import (
    _build_pass_region_evidence_map as _build_pass_region_evidence_map_impl,
)
from r2morph.core.report_helpers_evidence_summary import (
    _summarize_pass_evidence as _summarize_pass_evidence_impl,
)
from r2morph.core.report_helpers_observables import (
    _build_observable_mismatch_map as _build_observable_mismatch_map,
)
from r2morph.core.report_helpers_observables import (
    _build_observable_mismatch_priority as _build_observable_mismatch_priority,
)
from r2morph.core.report_helpers_observables import (
    _summarize_observable_mismatches_by_pass as _summarize_observable_mismatches_by_pass,
)
from r2morph.core.report_helpers_projection import (
    _build_pass_capability_summary_map as _build_pass_capability_summary_map,
)
from r2morph.core.report_helpers_projection import (
    _summarize_pass_capability_rows as _summarize_pass_capability_rows,
)
from r2morph.core.report_helpers_structural_evidence import (
    _summarize_structural_evidence as _summarize_structural_evidence_summary,
)
from r2morph.core.report_helpers_summary_metrics import (
    _summarize_diff_digest as _summarize_diff_digest_summary,
)
from r2morph.core.report_helpers_summary_metrics import (
    _summarize_pass_timings as _summarize_pass_timings_summary,
)


def _summarize_pass_timings(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a compact per-pass timing summary for tooling."""
    return _summarize_pass_timings_summary(pass_results)


def _summarize_diff_digest(pass_results: dict[str, Any]) -> dict[str, Any]:
    """Build a compact diff digest across passes."""
    return _summarize_diff_digest_summary(pass_results)


def _summarize_structural_evidence(
    structural_regions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a compact structural-evidence digest from region-level findings."""
    return _summarize_structural_evidence_summary(structural_regions)


def _build_evidence_summary_for_pass(
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
                "original_region_exit_steps": metadata.get(
                    "symbolic_binary_original_region_exit_steps",
                    0,
                ),
                "mutated_region_exit_steps": metadata.get(
                    "symbolic_binary_mutated_region_exit_steps",
                    0,
                ),
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


def _summarize_pass_evidence(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Aggregate per-pass evidence summaries for tooling."""
    return _summarize_pass_evidence_impl(pass_results)


def _build_pass_region_evidence_map(
    pass_results: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Persist compact symbolic region evidence by pass for report consumers."""
    return _build_pass_region_evidence_map_impl(pass_results)


def _summarize_normalized_pass_results(
    pass_results: dict[str, Any],
    *,
    pass_triage_map: dict[str, Any],
    pass_capability_summary_map: dict[str, Any],
    validation_role_map: dict[str, Any],
    pass_evidence_map: dict[str, Any],
    pass_symbolic_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a compact normalized per-pass view for tooling/report consumers."""
    rows: list[dict[str, Any]] = []
    for pass_name in sorted(pass_results):
        symbolic_summary = dict(pass_symbolic_summary.get(pass_name, {}) or {})
        evidence = dict(pass_evidence_map.get(pass_name, {}) or {})
        triage = dict(pass_triage_map.get(pass_name, {}) or {})
        capability = dict(pass_capability_summary_map.get(pass_name, {}) or {})
        validation_context = dict(validation_role_map.get(pass_name, {}) or {})
        rows.append(
            {
                "pass_name": pass_name,
                "status": pass_results.get(pass_name, {}).get("status", "unknown"),
                "mutations_applied": int(pass_results.get(pass_name, {}).get("mutations_applied", 0)),
                "severity": symbolic_summary.get(
                    "severity",
                    triage.get("severity", "not-requested"),
                ),
                "issue_count": int(symbolic_summary.get("issue_count", 0)),
                "structural_issue_count": int(evidence.get("structural_issue_count", 0)),
                "symbolic_binary_mismatched_regions": int(evidence.get("symbolic_binary_mismatched_regions", 0)),
                "changed_region_count": int(evidence.get("changed_region_count", 0)),
                "changed_bytes": int(evidence.get("changed_bytes", 0)),
                "runtime_recommended": bool(capability.get("runtime_recommended", False)),
                "symbolic_recommended": bool(capability.get("symbolic_recommended", False)),
                "symbolic_confidence": capability.get("symbolic_confidence", "unknown"),
                "role": validation_context.get("role", "requested-mode"),
                "symbolic_requested": int(symbolic_summary.get("symbolic_requested", 0)),
                "observable_match": int(symbolic_summary.get("observable_match", 0)),
                "observable_mismatch": int(symbolic_summary.get("observable_mismatch", 0)),
                "bounded_only": int(symbolic_summary.get("bounded_only", 0)),
                "without_coverage": int(symbolic_summary.get("without_coverage", 0)),
            }
        )
    return rows
