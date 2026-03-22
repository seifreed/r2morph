"""
Main morphing engine for binary transformations.
"""

import logging
import os
import platform
import random
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.constants import (
    BATCH_MUTATION_CHECKPOINT,
    LARGE_BINARY_THRESHOLD_MB,
    LARGE_FUNCTION_COUNT_THRESHOLD,
    MANY_FUNCTIONS_THRESHOLD,
    MEDIUM_FUNCTION_COUNT_THRESHOLD,
    VERY_MANY_FUNCTIONS_THRESHOLD,
)
from r2morph.mutations.base import MutationPass
from r2morph.pipeline.pipeline import Pipeline
from r2morph.reporting.gate_evaluator import (
    SEVERITY_ORDER,
    build_gate_failure_priority,
    build_gate_failure_severity_priority,
    summarize_gate_failures,
)

# Backward-compatible aliases (underscore-prefixed names used throughout engine)
_summarize_gate_failures = summarize_gate_failures
_build_gate_failure_priority = build_gate_failure_priority
_build_gate_failure_severity_priority = build_gate_failure_severity_priority
from r2morph.reporting.report_view_builder import _build_report_views
from r2morph.platform.codesign import CodeSigner
from r2morph.core.support import PRODUCT_SUPPORT, classify_target_support
from r2morph.session import MorphSession
from r2morph.validation import BinaryValidator, ValidationManager

logger = logging.getLogger(__name__)

REPORT_SCHEMA_VERSION = 1



def _build_pass_validation_context(
    pass_name: str,
    *,
    requested_mode: str,
    effective_mode: str,
    validation_policy: dict[str, Any] | None,
) -> dict[str, Any]:
    """Describe how validation mode applied to an individual pass."""
    limited_passes = list((validation_policy or {}).get("limited_passes", []))
    trigger = next((item for item in limited_passes if item.get("pass_name") == pass_name), None)
    degraded_execution = requested_mode != effective_mode
    if trigger is not None:
        role = "degradation-trigger"
    elif degraded_execution:
        role = "executed-under-degraded-mode"
    else:
        role = "requested-mode"
    return {
        "requested_validation_mode": requested_mode,
        "effective_validation_mode": effective_mode,
        "degraded_execution": degraded_execution,
        "degradation_triggered_by_pass": trigger is not None,
        "degradation_policy": (validation_policy or {}).get("policy"),
        "degradation_reason": (validation_policy or {}).get("reason"),
        "degradation_trigger": trigger,
        "role": role,
    }


def _enrich_validation_policy(
    validation_policy: dict[str, Any] | None,
    pass_results: dict[str, Any],
) -> dict[str, Any] | None:
    """Attach per-pass role metadata to validation policy for machine-readable consumers."""
    if validation_policy is None:
        return None

    enriched = dict(validation_policy)
    enriched_limited_passes = []
    for item in validation_policy.get("limited_passes", []):
        entry = dict(item)
        pass_name = entry.get("pass_name")
        role = None
        if pass_name is not None:
            role = pass_results.get(pass_name, {}).get("validation_context", {}).get("role")
        if role is not None:
            entry["role"] = role
        enriched_limited_passes.append(entry)
    enriched["limited_passes"] = enriched_limited_passes
    return enriched


def _summarize_degradation_roles(
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


def _summarize_symbolic_issue_passes(
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

    issue_rows = []
    for pass_name, stats in by_pass.items():
        if stats["observable_mismatch"] == 0 and stats["without_coverage"] == 0 and stats["bounded_only"] == 0:
            continue
        severity = (
            "mismatch"
            if stats["observable_mismatch"] > 0
            else "without-coverage"
            if stats["without_coverage"] > 0
            else "bounded-only"
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
            -item["observable_mismatch"],
            -item["without_coverage"],
            -item["bounded_only"],
            item["pass_name"],
        )
    )
    return issue_rows


def _summarize_symbolic_coverage_by_pass(
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

    rows = []
    for pass_name, stats in by_pass.items():
        rows.append({"pass_name": pass_name, **stats})
    rows.sort(
        key=lambda item: (
            -item["symbolic_requested"],
            -item["observable_match"],
            -item["observable_mismatch"],
            item["pass_name"],
        )
    )
    return rows


def _summarize_observable_mismatches_by_pass(
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


def _build_observable_mismatch_map(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Build a machine-readable lookup for observable mismatches by pass."""
    return {str(row.get("pass_name")): dict(row) for row in rows if row.get("pass_name")}


def _build_observable_mismatch_priority(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a stable priority view for observable mismatches."""
    priority = [dict(row) for row in rows]
    priority.sort(
        key=lambda item: (
            -int(item.get("mismatch_count", 0)),
            -len(item.get("observables", [])),
            str(item.get("pass_name", "")),
        )
    )
    return priority


def _summarize_symbolic_statuses(
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
    rows = [
        {
            "pass_name": pass_name,
            "statuses": dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))),
        }
        for pass_name, counts in by_pass.items()
    ]
    rows.sort(
        key=lambda item: (
            -sum(item["statuses"].values()),
            item["pass_name"],
        )
    )
    return (
        dict(sorted(global_counts.items(), key=lambda item: (-item[1], item[0]))),
        rows,
        {row["pass_name"]: dict(row["statuses"]) for row in rows},
    )


def _build_symbolic_summary_for_pass(
    pass_name: str,
    mutations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a symbolic coverage/issues summary for one pass."""
    pass_mutations = [mutation for mutation in mutations if mutation.get("pass_name", "unknown") == pass_name]
    coverage_rows = _summarize_symbolic_coverage_by_pass(pass_mutations)
    issue_rows = _summarize_symbolic_issue_passes(pass_mutations)
    coverage = (
        coverage_rows[0]
        if coverage_rows
        else {
            "pass_name": pass_name,
            "symbolic_requested": 0,
            "observable_match": 0,
            "observable_mismatch": 0,
            "bounded_only": 0,
            "without_coverage": 0,
        }
    )
    severity = (
        issue_rows[0]["severity"] if issue_rows else "clean" if coverage["symbolic_requested"] > 0 else "not-requested"
    )
    return {
        **coverage,
        "severity": severity,
        "issue_count": len(issue_rows),
        "issues": issue_rows,
    }


def _summarize_symbolic_severity_by_pass(
    pass_results: dict[str, Any],
) -> list[dict[str, Any]]:
    """Aggregate symbolic severity by pass from per-pass summaries."""
    rows = []
    for pass_name, pass_result in pass_results.items():
        symbolic_summary = pass_result.get("symbolic_summary", {})
        rows.append(
            {
                "pass_name": pass_name,
                "severity": symbolic_summary.get("severity", "not-requested"),
                "issue_count": symbolic_summary.get("issue_count", 0),
                "symbolic_requested": symbolic_summary.get("symbolic_requested", 0),
            }
        )
    severity_order = SEVERITY_ORDER
    rows.sort(
        key=lambda item: (
            severity_order.get(item["severity"], 99),
            -item["issue_count"],
            -item["symbolic_requested"],
            item["pass_name"],
        )
    )
    return rows


def _summarize_pass_capability_rows(
    pass_capabilities: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a compact triage-oriented capabilities summary."""
    rows = []
    for pass_name, capabilities in pass_capabilities.items():
        runtime = dict(capabilities.get("runtime", {}) or {})
        symbolic = dict(capabilities.get("symbolic", {}) or {})
        rows.append(
            {
                "pass_name": pass_name,
                "runtime_recommended": bool(runtime.get("recommended", False)),
                "symbolic_recommended": bool(symbolic.get("recommended", False)),
                "symbolic_confidence": symbolic.get("confidence", "unknown"),
            }
        )
    rows.sort(
        key=lambda item: (
            0 if item["runtime_recommended"] else 1,
            0 if item["symbolic_recommended"] else 1,
            item["pass_name"],
        )
    )
    return rows


def _build_pass_capability_summary_map(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index capability rows by pass name."""
    return {str(row.get("pass_name")): dict(row) for row in rows if row.get("pass_name")}


def _summarize_validation_role_rows(
    pass_validation_context: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a compact summary of validation role per pass."""
    rows = []
    for pass_name, context in pass_validation_context.items():
        rows.append(
            {
                "pass_name": pass_name,
                "role": context.get("role", "unknown"),
                "requested_validation_mode": context.get("requested_validation_mode", "off"),
                "effective_validation_mode": context.get("effective_validation_mode", "off"),
                "degraded_execution": bool(context.get("degraded_execution", False)),
            }
        )
    rows.sort(
        key=lambda item: (
            0 if item["role"] == "degradation-trigger" else 1,
            0 if item["role"] == "executed-under-degraded-mode" else 1,
            item["pass_name"],
        )
    )
    return rows


def _build_validation_role_map(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index validation role rows by pass name."""
    return {str(row.get("pass_name")): dict(row) for row in rows if row.get("pass_name")}


def _summarize_validation_adjustments(
    *,
    requested_mode: str,
    effective_mode: str,
    validation_policy: dict[str, Any] | None,
    validation_role_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize validation mode adjustments for report consumers."""
    limited_passes = list((validation_policy or {}).get("limited_passes", []))
    trigger_passes = [item.get("pass_name", item.get("mutation", "unknown")) for item in limited_passes]
    degraded_passes = [
        row["pass_name"] for row in validation_role_rows if row.get("role") == "executed-under-degraded-mode"
    ]
    return {
        "requested_validation_mode": requested_mode,
        "effective_validation_mode": effective_mode,
        "degraded_validation": requested_mode != effective_mode,
        "policy": (validation_policy or {}).get("policy"),
        "reason": (validation_policy or {}).get("reason"),
        "trigger_passes": trigger_passes,
        "executed_under_degraded_mode_passes": degraded_passes,
    }


def _summarize_pass_coverage_buckets(pass_results: dict[str, Any]) -> dict[str, list[str]]:
    """Build machine-readable coverage buckets across passes."""
    covered: list[str] = []
    uncovered: list[str] = []
    clean_only: list[str] = []
    for pass_name, pass_result in pass_results.items():
        evidence = pass_result.get("evidence_summary", {}) or {}
        symbolic = pass_result.get("symbolic_summary", {}) or {}
        structural_issues = int(evidence.get("structural_issue_count", 0))
        symbolic_mismatch = int(evidence.get("symbolic_binary_mismatched_regions", 0))
        severity = str(symbolic.get("severity", "not-requested"))
        issue_count = int(symbolic.get("issue_count", 0))
        clean = (
            structural_issues == 0
            and symbolic_mismatch == 0
            and severity in {"clean", "not-requested"}
            and issue_count == 0
        )
        if not clean:
            continue
        clean_only.append(pass_name)
        symbolic_requested = int(symbolic.get("symbolic_requested", 0))
        without_coverage = int(symbolic.get("without_coverage", 0))
        checked_regions = int(evidence.get("symbolic_binary_regions_checked", 0))
        if symbolic_requested > 0 and without_coverage == 0 and checked_regions > 0:
            covered.append(pass_name)
        else:
            uncovered.append(pass_name)
    return {
        "covered": sorted(covered),
        "uncovered": sorted(uncovered),
        "clean_only": sorted(clean_only),
    }


def _summarize_pass_risk_buckets(
    pass_results: dict[str, Any],
) -> dict[str, list[str]]:
    """Build machine-readable risk buckets across passes."""
    risky: list[str] = []
    structural: list[str] = []
    symbolic: list[str] = []
    clean: list[str] = []
    for pass_name, pass_result in pass_results.items():
        evidence = pass_result.get("evidence_summary", {}) or {}
        symbolic_summary = pass_result.get("symbolic_summary", {}) or {}
        structural_issues = int(evidence.get("structural_issue_count", 0))
        symbolic_mismatch = int(evidence.get("symbolic_binary_mismatched_regions", 0))
        severity = str(symbolic_summary.get("severity", "not-requested"))
        issue_count = int(symbolic_summary.get("issue_count", 0))
        has_structural_risk = structural_issues > 0
        has_symbolic_risk = (
            symbolic_mismatch > 0 or severity in {"mismatch", "without-coverage", "bounded-only"} or issue_count > 0
        )
        if has_structural_risk or has_symbolic_risk:
            risky.append(pass_name)
        if has_structural_risk:
            structural.append(pass_name)
        if has_symbolic_risk:
            symbolic.append(pass_name)
        if (
            structural_issues == 0
            and symbolic_mismatch == 0
            and severity in {"clean", "not-requested"}
            and issue_count == 0
        ):
            clean.append(pass_name)
    coverage = _summarize_pass_coverage_buckets(pass_results)
    return {
        "risky": sorted(risky),
        "structural": sorted(structural),
        "symbolic": sorted(symbolic),
        "clean": sorted(clean),
        "covered": coverage["covered"],
        "uncovered": coverage["uncovered"],
    }


def _summarize_pass_timings(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a compact per-pass timing summary for tooling."""
    rows = []
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
    rows.sort(key=lambda item: (-item["execution_time_seconds"], item["pass_name"]))
    return rows


def _summarize_diff_digest(pass_results: dict[str, Any]) -> dict[str, Any]:
    """Build a compact diff digest across passes."""
    digest = {
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
        digest["changed_region_count"] += len(changed_regions)
        digest["changed_bytes"] += changed_bytes
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
        key=lambda item: (-item["changed_bytes"], -item["changed_region_count"], item["pass_name"])
    )
    digest["mutation_kinds"] = sorted(mutation_kinds)
    digest["passes_with_changes"] = passes_with_changes
    return digest


def _summarize_structural_evidence(
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
    rows = []
    for pass_name, pass_result in pass_results.items():
        evidence_summary = pass_result.get("evidence_summary", {})
        rows.append(
            {
                "pass_name": pass_name,
                "changed_region_count": evidence_summary.get("changed_region_count", 0),
                "structural_issue_count": evidence_summary.get("structural_issue_count", 0),
                "symbolic_binary_regions_checked": evidence_summary.get(
                    "symbolic_binary_regions_checked",
                    0,
                ),
                "symbolic_binary_mismatched_regions": evidence_summary.get(
                    "symbolic_binary_mismatched_regions",
                    0,
                ),
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


def _summarize_discarded_mutations(
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
    severity_order = SEVERITY_ORDER
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
    rows = [
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
            -item["discarded_count"],
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


def _build_discarded_mutation_priority(
    discarded_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a stable priority view for discarded mutations."""
    severity_order = SEVERITY_ORDER
    rows = [dict(row) for row in discarded_summary.get("by_pass", [])]
    rows.sort(
        key=lambda item: (
            severity_order.get(str(item.get("impact_severity", "low")), 99),
            -int(item.get("discarded_count", 0)),
            -len(item.get("reasons", {})),
            str(item.get("pass_name", "")),
        )
    )
    return rows


def _summarize_pass_triage_rows(
    pass_results: dict[str, Any],
    pass_capability_summary_map: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build one compact triage row per pass for CLI/report consumers."""
    severity_order = SEVERITY_ORDER
    rows = []
    for pass_name, pass_result in pass_results.items():
        symbolic_summary = dict(pass_result.get("symbolic_summary", {}) or {})
        evidence_summary = dict(pass_result.get("evidence_summary", {}) or {})
        validation_context = dict(pass_result.get("validation_context", {}) or {})
        capability_summary = dict(pass_capability_summary_map.get(pass_name, {}) or {})
        severity = symbolic_summary.get("severity", "not-requested")
        rows.append(
            {
                "pass_name": pass_name,
                "severity": severity,
                "severity_order": severity_order.get(severity, 99),
                "issue_count": int(symbolic_summary.get("issue_count", 0)),
                "symbolic_requested": int(symbolic_summary.get("symbolic_requested", 0)),
                "observable_match": int(symbolic_summary.get("observable_match", 0)),
                "observable_mismatch": int(symbolic_summary.get("observable_mismatch", 0)),
                "bounded_only": int(symbolic_summary.get("bounded_only", 0)),
                "without_coverage": int(symbolic_summary.get("without_coverage", 0)),
                "structural_issue_count": int(evidence_summary.get("structural_issue_count", 0)),
                "symbolic_binary_mismatched_regions": int(
                    evidence_summary.get("symbolic_binary_mismatched_regions", 0)
                ),
                "changed_region_count": int(evidence_summary.get("changed_region_count", 0)),
                "changed_bytes": int(evidence_summary.get("changed_bytes", 0)),
                "role": validation_context.get("role", "requested-mode"),
                "degraded_execution": bool(validation_context.get("degraded_execution", False)),
                "runtime_recommended": bool(capability_summary.get("runtime_recommended", False)),
                "symbolic_recommended": bool(capability_summary.get("symbolic_recommended", False)),
                "symbolic_confidence": capability_summary.get("symbolic_confidence", "unknown"),
            }
        )
    rows.sort(
        key=lambda item: (
            severity_order.get(item["severity"], 99),
            -item["symbolic_binary_mismatched_regions"],
            -item["structural_issue_count"],
            -item["changed_region_count"],
            item["pass_name"],
        )
    )
    return rows


def _summarize_symbolic_overview(
    symbolic_coverage_by_pass: list[dict[str, Any]],
    symbolic_status_counts: dict[str, int],
) -> dict[str, Any]:
    """Build a compact global symbolic overview."""
    overview = {
        "symbolic_requested": 0,
        "observable_match": 0,
        "observable_mismatch": 0,
        "bounded_only": 0,
        "without_coverage": 0,
        "statuses": dict(symbolic_status_counts),
    }
    for row in symbolic_coverage_by_pass:
        overview["symbolic_requested"] += int(row.get("symbolic_requested", 0))
        overview["observable_match"] += int(row.get("observable_match", 0))
        overview["observable_mismatch"] += int(row.get("observable_mismatch", 0))
        overview["bounded_only"] += int(row.get("bounded_only", 0))
        overview["without_coverage"] += int(row.get("without_coverage", 0))
    return overview


def _summarize_pass_evidence_compact(
    pass_triage_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a compact evidence/triage view ready for rendering."""
    rows = [
        {
            "pass_name": row.get("pass_name"),
            "severity": row.get("severity", "unknown"),
            "structural_issue_count": row.get("structural_issue_count", 0),
            "symbolic_binary_mismatched_regions": row.get("symbolic_binary_mismatched_regions", 0),
            "changed_region_count": row.get("changed_region_count", 0),
            "changed_bytes": row.get("changed_bytes", 0),
            "role": row.get("role", "unknown"),
            "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
        }
        for row in pass_triage_rows
        if row.get("pass_name")
    ]
    return rows


def _build_pass_region_evidence_map(
    pass_results: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Persist compact symbolic region evidence by pass for report consumers."""
    region_map: dict[str, list[dict[str, Any]]] = {}
    for pass_name, pass_result in pass_results.items():
        evidence = dict(pass_result.get("evidence_summary", {}) or {})
        symbolic_regions = list(evidence.get("symbolic_regions", []) or [])
        if not symbolic_regions:
            continue
        region_map[pass_name] = [
            {
                "start_address": row.get("start_address"),
                "end_address": row.get("end_address"),
                "equivalent": bool(row.get("equivalent", False)),
                "mismatch_count": int(row.get("mismatch_count", len(row.get("mismatches", [])))),
                "mismatches": list(row.get("mismatches", [])),
                "step_strategy": row.get("step_strategy"),
                "region_exit_equivalent": (
                    row.get("original_region_exit_address") == row.get("mutated_region_exit_address")
                    and row.get("original_region_exit_address") is not None
                ),
                "original_region_exit_address": row.get("original_region_exit_address"),
                "mutated_region_exit_address": row.get("mutated_region_exit_address"),
                "original_trace_length": int(row.get("original_trace_length", 0)),
                "mutated_trace_length": int(row.get("mutated_trace_length", 0)),
                "original_region_exit_steps": int(row.get("original_region_exit_steps", 0)),
                "mutated_region_exit_steps": int(row.get("mutated_region_exit_steps", 0)),
            }
            for row in symbolic_regions
        ]
    return region_map


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





def _summarize_validation_adjustment_rows(
    validation_role_rows: list[dict[str, Any]],
    validation_adjustments: dict[str, Any],
    gate_failures: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Build a compact per-pass adjustment/gate view for report consumers."""
    failed_by_pass = dict((gate_failures or {}).get("require_pass_severity_failures_by_pass", {}))
    rows: list[dict[str, Any]] = []
    degraded_validation = bool(validation_adjustments.get("degraded_validation", False))
    trigger_passes = set(validation_adjustments.get("trigger_passes", []) or [])
    degraded_passes = set(validation_adjustments.get("executed_under_degraded_mode_passes", []) or [])
    for row in validation_role_rows:
        pass_name = str(row.get("pass_name", ""))
        if not pass_name:
            continue
        rows.append(
            {
                "pass_name": pass_name,
                "role": row.get("role", "requested-mode"),
                "degraded_validation": degraded_validation,
                "triggered_adjustment": pass_name in trigger_passes,
                "executed_under_degraded_mode": pass_name in degraded_passes,
                "gate_failures": list(failed_by_pass.get(pass_name, [])),
                "gate_failure_count": len(failed_by_pass.get(pass_name, [])),
            }
        )
    return rows


def _build_pass_triage_map(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index triage rows by pass name."""
    return {str(row.get("pass_name")): dict(row) for row in rows if row.get("pass_name")}


class MorphEngine:
    """
    Main engine for orchestrating binary transformations.

    The engine manages the binary analysis, applies mutation passes through
    a pipeline, and handles the output generation.

    Attributes:
        binary: Binary instance being transformed
        pipeline: Transformation pipeline
        config: Engine configuration
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the MorphEngine.

        Args:
            config: Optional configuration dictionary
        """
        self.binary: Binary | None = None
        self.pipeline = Pipeline()
        self.config = config or {}
        self._stats: dict[str, Any] = {}
        self._memory_efficient_mode = False
        self._session: MorphSession | None = None
        self._last_result: dict[str, Any] | None = None

    @property
    def mutations(self) -> list[MutationPass]:
        """
        Get list of registered mutation passes.

        Returns:
            List of mutation passes in the pipeline
        """
        return self.pipeline.passes

    def _should_use_low_memory(self, path: Path) -> bool:
        """Determine if low-memory mode should be enabled based on file size."""
        binary_size_mb = os.path.getsize(path) / (1024 * 1024)
        return binary_size_mb > LARGE_BINARY_THRESHOLD_MB

    def _create_working_copy(self, original_path: Path) -> Path:
        """Create a temporary working copy of the binary."""
        temp_dir = Path(tempfile.gettempdir()) / "r2morph"
        temp_dir.mkdir(exist_ok=True)
        working_copy = temp_dir / f"{original_path.name}.working"
        shutil.copy2(original_path, working_copy)
        return working_copy

    def _get_binary_size_mb(self, path: Path) -> float:
        """Get binary file size in megabytes."""
        return os.path.getsize(path) / (1024 * 1024)

    def _should_enable_memory_efficient_mode(self, binary_size_mb: float, function_count: int) -> bool:
        """Determine if memory-efficient mode should be enabled."""
        return binary_size_mb > LARGE_BINARY_THRESHOLD_MB or function_count > LARGE_FUNCTION_COUNT_THRESHOLD

    def load_binary(self, path: str | Path, writable: bool = True) -> "MorphEngine":
        """
        Load a binary for transformation.

        Args:
            path: Path to binary file
            writable: Open in write mode for mutations (default: True)

        Returns:
            Self for method chaining
        """
        path = Path(path)
        logger.info(f"Loading binary: {path}")

        if writable:
            self._session = MorphSession()
            working_copy = self._session.start(path)
            logger.debug(f"Created session working copy: {working_copy}")
            self._original_path = path
            target_path = working_copy
        else:
            self._original_path = None
            target_path = path

        low_memory = self._should_use_low_memory(target_path)
        self.binary = Binary(target_path, writable=writable, low_memory=low_memory)
        self.binary.open()

        return self

    def analyze(self, level: str = "auto") -> "MorphEngine":
        """
        Analyze the loaded binary.

        Args:
            level: Analysis level (aa, aac, aaa, aaaa, or "auto" for adaptive)
                - aa: Basic analysis (fast, ~5s for 7k functions)
                - aac: Call analysis (fast, finds most functions)
                - aaa: Full analysis (SLOW on large binaries, recommended < 1000 functions)
                - aaaa: Experimental (very slow)
                - auto: Automatically choose based on binary size (default)

        Returns:
            Self for method chaining
        """
        if not self.binary:
            raise RuntimeError("No binary loaded. Call load_binary() first.")

        # Auto-detect best analysis level based on function count and size
        if level == "auto":
            level = self._auto_detect_analysis_level()
        else:
            # Manual level specified
            logger.info(f"Analyzing binary with level: {level}...")
            self.binary.analyze(level)

        functions = self.binary.get_functions()
        arch_info = self.binary.get_arch_info()

        self._stats = {
            "functions": len(functions),
            "arch": arch_info.get("arch"),
            "bits": arch_info.get("bits"),
            "format": arch_info.get("format"),
        }

        logger.info(f"Analysis complete. Found {len(functions)} functions")
        logger.debug(f"Architecture: {arch_info}")

        # Enable memory-efficient mode for large binaries to prevent OOM
        binary_size_mb = self._get_binary_size_mb(self.binary.path)
        if self._should_enable_memory_efficient_mode(binary_size_mb, len(functions)):
            self._memory_efficient_mode = True
            logger.warning(
                f"Large binary detected ({binary_size_mb:.1f} MB, {len(functions)} functions). "
                f"Enabling memory-efficient mode to prevent OOM crashes."
            )
            logger.info(
                f"Memory-efficient mode: reduced mutations per function, "
                f"batch processing with r2 restarts every {BATCH_MUTATION_CHECKPOINT} mutations."
            )

        return self

    def _auto_detect_analysis_level(self) -> str:
        """Auto-detect optimal analysis level based on binary complexity."""
        import time

        # Step 1: Quick basic analysis to count functions
        logger.info("Running quick analysis to estimate complexity...")
        start = time.time()
        self.binary.analyze("aa")
        quick_funcs = len(self.binary.get_functions())
        aa_time = time.time() - start

        # Calculate average function size
        binary_size_mb = self._get_binary_size_mb(self.binary.path)
        avg_func_size = (binary_size_mb * 1024 * 1024) / quick_funcs if quick_funcs > 0 else 0

        logger.info(
            f"Binary stats: {quick_funcs} functions, {binary_size_mb:.1f} MB, "
            f"avg {avg_func_size:.0f} bytes/func (aa took {aa_time:.1f}s)"
        )

        # Step 2: Decide analysis level based on complexity
        if quick_funcs > VERY_MANY_FUNCTIONS_THRESHOLD:
            level = "aa"  # Already done
            logger.warning(
                f"Very large binary ({quick_funcs} functions). Using fast analysis level 'aa' (already complete)."
            )
        elif quick_funcs > MANY_FUNCTIONS_THRESHOLD:
            level = "aac"  # Add call analysis
            logger.warning(
                f"Large binary ({quick_funcs} functions). Using 'aac' analysis (adds ~10-20s for call analysis)."
            )
            self.binary.analyze("aac")
        elif quick_funcs > MEDIUM_FUNCTION_COUNT_THRESHOLD:
            level = "aac"
            logger.info(f"Medium binary ({quick_funcs} functions). Using 'aac' analysis.")
            self.binary.analyze("aac")
        else:
            level = "aaa"
            logger.info(
                f"Small binary ({quick_funcs} functions). Using full 'aaa' analysis (~{int(aa_time * 3)}s estimated)."
            )
            self.binary.analyze("aaa")

        return level

    def add_mutation(self, mutation: MutationPass) -> "MorphEngine":
        """
        Add a mutation pass to the pipeline.

        Automatically adjusts mutation parameters when in memory-efficient mode.

        Args:
            mutation: Mutation pass to add

        Returns:
            Self for method chaining
        """
        # Adjust mutation config for large binaries to prevent OOM
        if self._memory_efficient_mode:
            mutation.configure_for_memory_constraints(0.4)

        self.pipeline.add_pass(mutation)
        logger.debug(f"Added mutation: {mutation.__class__.__name__}")
        return self

    def remove_mutation(self, mutation_name: str) -> "MorphEngine":
        """
        Remove a mutation pass from the pipeline by name.

        Args:
            mutation_name: Name of the mutation to remove

        Returns:
            Self for method chaining
        """
        self.pipeline.passes = [
            p for p in self.pipeline.passes if getattr(p, "name", p.__class__.__name__) != mutation_name
        ]
        logger.debug(f"Removed mutation: {mutation_name}")
        return self

    def run(
        self,
        *,
        validation_mode: str = "structural",
        rollback_policy: str = "skip-invalid-pass",
        checkpoint_per_mutation: bool = False,
        runtime_validator: BinaryValidator | None = None,
        runtime_validate_per_pass: bool = False,
        report_path: str | Path | None = None,
        seed: int | None = None,
    ) -> dict[str, Any]:
        """
        Run the transformation pipeline on the binary.

        Returns:
            Dictionary with transformation statistics and results
        """
        if not self.binary:
            raise RuntimeError("No binary loaded. Call load_binary() first.")

        if not self.binary.is_analyzed():
            logger.warning("Binary not analyzed. Running automatic analysis...")
            self.analyze()

        logger.info("Starting transformation pipeline...")
        start_time = time.time()
        if seed is not None:
            self.config["seed"] = int(seed)
            random.seed(seed)
            for index, mutation in enumerate(self.pipeline.passes):
                pass_seed = int(seed) + index
                mutation.config["_pass_seed"] = pass_seed
                mutation.config["_use_derived_seed"] = True

        validation_manager = None
        if validation_mode not in {"off", "runtime"}:
            validation_manager = ValidationManager(mode=validation_mode)

        result = self.pipeline.run(
            self.binary,
            session=self._session,
            validation_manager=validation_manager,
            runtime_validator=runtime_validator,
            runtime_validate_per_pass=runtime_validate_per_pass or validation_mode == "runtime",
            rollback_policy=rollback_policy,
            checkpoint_per_mutation=checkpoint_per_mutation,
        )

        if runtime_validator is not None and self._original_path is not None:
            runtime_result = runtime_validator.validate(self._original_path, self.binary.path)
            result["validation"]["runtime"] = runtime_result.to_dict()
            result["validation"]["all_passed"] = result["validation"].get("all_passed", True) and runtime_result.passed
            if not runtime_result.passed and self._session is not None:
                self._session.rollback_to("initial")
                self.binary.reload()
                if rollback_policy == "fail-fast":
                    raise RuntimeError("Runtime validation failed after pipeline execution")

        requested_validation_mode = self.config.get("requested_validation_mode", validation_mode)
        effective_validation_mode = self.config.get("effective_validation_mode", validation_mode)
        validation_policy = self.config.get("validation_policy")
        for pass_name, pass_result in result.get("pass_results", {}).items():
            pass_result["validation_context"] = _build_pass_validation_context(
                pass_name,
                requested_mode=requested_validation_mode,
                effective_mode=effective_validation_mode,
                validation_policy=validation_policy,
            )
        result["requested_validation_mode"] = requested_validation_mode
        result["validation_mode"] = effective_validation_mode
        enriched_validation_policy = _enrich_validation_policy(
            validation_policy,
            result.get("pass_results", {}),
        )
        if enriched_validation_policy is not None:
            result["validation_policy"] = enriched_validation_policy
        result["execution_time_seconds"] = round(time.time() - start_time, 3)
        result["input_path"] = str(self._original_path or self.binary.path)
        result["working_path"] = str(self.binary.path)
        result["config"] = dict(self.config)
        self._last_result = {**self._stats, **result}

        if report_path is not None:
            self.save_report(report_path, self._last_result)

        logger.info("Transformation complete")
        return self._last_result

    def save(self, output_path: str | Path):
        """
        Save the transformed binary.

        Args:
            output_path: Output file path
        """
        if not self.binary:
            raise RuntimeError("No binary loaded.")

        output_path = Path(output_path)

        logger.info(f"Saving transformed binary to: {output_path}")

        if self._session is not None:
            self._session.finalize(output_path)
        else:
            shutil.copy2(self.binary.path, output_path)
            logger.info(f"Binary successfully saved to: {output_path}")

        if platform.system() == "Darwin":
            entitlements = self.config.get("codesign_entitlements")
            if entitlements:
                entitlements = Path(entitlements)
            hardened = bool(self.config.get("codesign_hardened", False))
            timestamp = bool(self.config.get("codesign_timestamp", False))

            from r2morph.platform.macho_handler import MachOHandler

            handler = MachOHandler(output_path)
            if handler.is_macho():
                ok, msg = handler.validate_integrity()
                if not ok:
                    logger.warning(f"Mach-O layout check failed: {msg}")
                repaired = handler.repair_integrity(
                    entitlements=entitlements,
                    hardened=hardened,
                    timestamp=timestamp,
                )
                if not repaired:
                    logger.warning(f"Mach-O repair/signing failed for: {output_path}")
                try:
                    output_path.chmod(output_path.stat().st_mode | 0o111)
                except OSError as e:
                    logger.warning(f"Failed to mark Mach-O executable: {e}")
            else:
                signer = CodeSigner()
                if not signer.sign_binary(
                    output_path,
                    adhoc=True,
                    entitlements=entitlements,
                    hardened=hardened,
                    timestamp=timestamp,
                ):
                    logger.warning(f"Ad-hoc signing failed for: {output_path}")

    def close(self):
        """Close and cleanup resources."""
        if self.binary:
            self.binary.close()
            self.binary = None
        if self._session is not None:
            self._session.cleanup()
            self._session = None

    def get_stats(self) -> dict[str, Any]:
        """Get transformation statistics."""
        return self._stats

    def _enrich_pass_results(
        self,
        pass_results: dict[str, Any],
        mutations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Enrich pass results with symbolic/evidence summaries and build derived maps."""
        symbolic_issue_passes = _summarize_symbolic_issue_passes(mutations)
        symbolic_coverage_by_pass = _summarize_symbolic_coverage_by_pass(mutations)
        symbolic_status_counts, symbolic_status_rows, symbolic_status_map = _summarize_symbolic_statuses(mutations)
        observable_mismatch_by_pass = _summarize_observable_mismatches_by_pass(mutations)
        for pass_name, pass_result in pass_results.items():
            pass_result["symbolic_summary"] = _build_symbolic_summary_for_pass(
                pass_name,
                mutations,
            )
            pass_result["evidence_summary"] = _build_evidence_summary_for_pass(
                pass_name,
                pass_result,
            )
        symbolic_severity_by_pass = _summarize_symbolic_severity_by_pass(pass_results)
        return {
            "symbolic_issue_passes": symbolic_issue_passes,
            "symbolic_coverage_by_pass": symbolic_coverage_by_pass,
            "symbolic_status_counts": symbolic_status_counts,
            "symbolic_status_rows": symbolic_status_rows,
            "symbolic_status_map": symbolic_status_map,
            "observable_mismatch_by_pass": observable_mismatch_by_pass,
            "observable_mismatch_map": _build_observable_mismatch_map(observable_mismatch_by_pass),
            "observable_mismatch_priority": _build_observable_mismatch_priority(observable_mismatch_by_pass),
            "symbolic_severity_by_pass": symbolic_severity_by_pass,
            "symbolic_issue_map": {
                str(row.get("pass_name")): dict(row) for row in symbolic_issue_passes if row.get("pass_name")
            },
            "symbolic_coverage_map": {
                str(row.get("pass_name")): dict(row) for row in symbolic_coverage_by_pass if row.get("pass_name")
            },
            "symbolic_severity_map": {
                str(row.get("pass_name")): dict(row) for row in symbolic_severity_by_pass if row.get("pass_name")
            },
            "pass_evidence": _summarize_pass_evidence(pass_results),
            "pass_coverage_buckets": _summarize_pass_coverage_buckets(pass_results),
            "pass_risk_buckets": _summarize_pass_risk_buckets(pass_results),
            "pass_symbolic_summary": {
                pass_name: dict(pass_result.get("symbolic_summary", {}))
                for pass_name, pass_result in pass_results.items()
                if pass_result.get("symbolic_summary")
            },
        }

    def _compute_report_artifacts(
        self,
        payload: dict[str, Any],
        pass_results: dict[str, Any],
        enrichments: dict[str, Any],
        aggregate_structural_regions: list[dict[str, Any]],
        gate_failures: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Compute validation/triage/view artifacts for the final report."""
        pass_validation_context = {
            pass_name: dict(pass_result.get("validation_context", {}))
            for pass_name, pass_result in pass_results.items()
            if pass_result.get("validation_context")
        }
        structural_evidence = _summarize_structural_evidence(aggregate_structural_regions)
        support_profile = classify_target_support(
            str(payload.get("format", "")),
            str(payload.get("arch", "")),
            int(payload["bits"]) if payload.get("bits") is not None else None,
        )
        pass_support = {mutation.name: mutation.get_support().to_dict() for mutation in self.pipeline.passes}
        pass_capabilities = {
            pass_name: support.get("validator_capabilities", {}) for pass_name, support in pass_support.items()
        }
        for pass_name in pass_results:
            pass_capabilities.setdefault(pass_name, {})
        pass_capability_summary = _summarize_pass_capability_rows(pass_capabilities)
        pass_capability_summary_map = _build_pass_capability_summary_map(pass_capability_summary)
        pass_evidence = enrichments["pass_evidence"]
        pass_evidence_map = {
            row.get("pass_name", "unknown"): dict(row) for row in pass_evidence if row.get("pass_name")
        }
        validation_role_rows = _summarize_validation_role_rows(pass_validation_context)
        validation_role_map = _build_validation_role_map(validation_role_rows)
        discarded_mutation_summary = _summarize_discarded_mutations(list(payload.get("discarded_mutations_detail", [])))
        discarded_mutation_priority = _build_discarded_mutation_priority(discarded_mutation_summary)
        pass_triage_rows = _summarize_pass_triage_rows(
            pass_results,
            pass_capability_summary_map,
        )
        pass_triage_map = _build_pass_triage_map(pass_triage_rows)
        pass_symbolic_summary = enrichments["pass_symbolic_summary"]
        symbolic_overview = _summarize_symbolic_overview(
            enrichments["symbolic_coverage_by_pass"],
            enrichments["symbolic_status_counts"],
        )
        pass_evidence_compact = _summarize_pass_evidence_compact(pass_triage_rows)
        pass_region_evidence_map = _build_pass_region_evidence_map(pass_results)
        normalized_pass_results = _summarize_normalized_pass_results(
            pass_results,
            pass_triage_map=pass_triage_map,
            pass_capability_summary_map=pass_capability_summary_map,
            validation_role_map=validation_role_map,
            pass_evidence_map=pass_evidence_map,
            pass_symbolic_summary=pass_symbolic_summary,
        )
        validation_adjustments = _summarize_validation_adjustments(
            requested_mode=payload.get(
                "requested_validation_mode",
                payload.get("validation_mode", "off"),
            ),
            effective_mode=payload.get("validation_mode", "off"),
            validation_policy=payload.get("validation_policy"),
            validation_role_rows=validation_role_rows,
        )
        validation_adjustment_rows = _summarize_validation_adjustment_rows(
            validation_role_rows,
            validation_adjustments,
            gate_failures if isinstance(gate_failures, dict) else {},
        )
        report_views = _build_report_views(
            pass_risk_buckets=enrichments["pass_risk_buckets"],
            pass_coverage_buckets=enrichments["pass_coverage_buckets"],
            pass_triage_rows=pass_triage_rows,
            normalized_pass_results=normalized_pass_results,
            pass_symbolic_summary=pass_symbolic_summary,
            pass_evidence_map=pass_evidence_map,
            pass_region_evidence_map=pass_region_evidence_map,
            pass_validation_context=pass_validation_context,
            pass_capability_summary_map=pass_capability_summary_map,
            observable_mismatch_priority=enrichments["observable_mismatch_priority"],
            observable_mismatch_map=enrichments["observable_mismatch_map"],
            symbolic_severity_by_pass=enrichments["symbolic_severity_by_pass"],
            gate_failure_priority=_build_gate_failure_priority(gate_failures),
            gate_failure_summary=gate_failures if isinstance(gate_failures, dict) else {},
            gate_failure_severity_priority=_build_gate_failure_severity_priority(gate_failures),
            discarded_mutation_priority=discarded_mutation_priority,
            discarded_mutation_summary=discarded_mutation_summary,
            validation_adjustment_rows=validation_adjustment_rows,
        )
        return {
            "pass_validation_context": pass_validation_context,
            "structural_evidence": structural_evidence,
            "support_profile": support_profile,
            "pass_support": pass_support,
            "pass_capabilities": pass_capabilities,
            "pass_capability_summary": pass_capability_summary,
            "pass_capability_summary_map": pass_capability_summary_map,
            "pass_evidence_map": pass_evidence_map,
            "validation_role_rows": validation_role_rows,
            "validation_role_map": validation_role_map,
            "discarded_mutation_summary": discarded_mutation_summary,
            "discarded_mutation_priority": discarded_mutation_priority,
            "pass_triage_rows": pass_triage_rows,
            "pass_triage_map": pass_triage_map,
            "symbolic_overview": symbolic_overview,
            "pass_evidence_compact": pass_evidence_compact,
            "pass_region_evidence_map": pass_region_evidence_map,
            "normalized_pass_results": normalized_pass_results,
            "validation_adjustments": validation_adjustments,
            "validation_adjustment_rows": validation_adjustment_rows,
            "report_views": report_views,
        }

    def build_report(self, result: dict[str, Any] | None = None) -> dict[str, Any]:
        """Build a stable machine-readable engine report."""
        payload = result or self._last_result or {}
        pass_results = {
            pass_name: dict(pass_result) for pass_name, pass_result in payload.get("pass_results", {}).items()
        }
        mutations = payload.get("mutations", [])
        aggregate_regions = []
        aggregate_changed_bytes = 0
        aggregate_structural_regions = []
        for pass_result in pass_results.values():
            diff_summary = pass_result.get("diff_summary", {})
            aggregate_regions.extend(diff_summary.get("changed_regions", []))
            aggregate_changed_bytes += int(diff_summary.get("changed_bytes", 0))
            aggregate_structural_regions.extend(diff_summary.get("structural_regions", []))
        degradation_role_counts = _summarize_degradation_roles(pass_results)
        pass_timing_summary = _summarize_pass_timings(pass_results)
        diff_digest = _summarize_diff_digest(pass_results)
        gate_evaluation = payload.get("gate_evaluation")
        gate_failures = (
            _summarize_gate_failures(gate_evaluation)
            if isinstance(gate_evaluation, dict)
            else payload.get("gate_failures")
        )
        gate_failure_priority = _build_gate_failure_priority(gate_failures)
        gate_failure_severity_priority = _build_gate_failure_severity_priority(gate_failures)
        enrichments = self._enrich_pass_results(pass_results, mutations)
        artifacts = self._compute_report_artifacts(
            payload, pass_results, enrichments, aggregate_structural_regions, gate_failures,
        )
        pass_evidence_priority = [dict(row) for row in enrichments["pass_evidence"]]
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "input": {
                "path": payload.get("input_path"),
                "arch": payload.get("arch"),
                "bits": payload.get("bits"),
                "format": payload.get("format"),
                "functions": payload.get("functions"),
            },
            "output": {
                "working_path": payload.get("working_path"),
            },
            "passes": pass_results,
            "pass_support": artifacts["pass_support"],
            "pass_capabilities": artifacts["pass_capabilities"],
            "pass_capability_summary": artifacts["pass_capability_summary"],
            "pass_capability_summary_map": artifacts["pass_capability_summary_map"],
            "mutations": mutations,
            "discarded_mutations": payload.get("discarded_mutations_detail", []),
            "discarded_mutation_summary": artifacts["discarded_mutation_summary"],
            "discarded_mutation_priority": artifacts["discarded_mutation_priority"],
            "gate_evaluation": gate_evaluation,
            "gate_failures": gate_failures,
            "gate_failure_priority": gate_failure_priority,
            "gate_failure_severity_priority": gate_failure_severity_priority,
            "validation": payload.get("validation", {}),
            "symbolic_issue_map": enrichments["symbolic_issue_map"],
            "symbolic_coverage_map": enrichments["symbolic_coverage_map"],
            "symbolic_severity_map": enrichments["symbolic_severity_map"],
            "symbolic_status_counts": enrichments["symbolic_status_counts"],
            "symbolic_status_rows": enrichments["symbolic_status_rows"],
            "symbolic_status_map": enrichments["symbolic_status_map"],
            "symbolic_overview": artifacts["symbolic_overview"],
            "observable_mismatch_by_pass": enrichments["observable_mismatch_by_pass"],
            "observable_mismatch_map": enrichments["observable_mismatch_map"],
            "observable_mismatch_priority": enrichments["observable_mismatch_priority"],
            "timings": {
                "execution_time_seconds": payload.get("execution_time_seconds", 0.0),
                "passes": pass_timing_summary,
            },
            "diff_digest": diff_digest,
            "pass_evidence": enrichments["pass_evidence"],
            "pass_evidence_priority": pass_evidence_priority,
            "pass_coverage_buckets": enrichments["pass_coverage_buckets"],
            "pass_risk_buckets": enrichments["pass_risk_buckets"],
            "pass_symbolic_summary": enrichments["pass_symbolic_summary"],
            "pass_validation_context": artifacts["pass_validation_context"],
            "validation_role_rows": artifacts["validation_role_rows"],
            "validation_role_map": artifacts["validation_role_map"],
            "pass_evidence_map": artifacts["pass_evidence_map"],
            "pass_region_evidence_map": artifacts["pass_region_evidence_map"],
            "pass_triage_rows": artifacts["pass_triage_rows"],
            "pass_triage_map": artifacts["pass_triage_map"],
            "pass_evidence_compact": artifacts["pass_evidence_compact"],
            "normalized_pass_results": artifacts["normalized_pass_results"],
            "report_views": artifacts["report_views"],
            "structural_evidence": artifacts["structural_evidence"],
            "validation_adjustments": artifacts["validation_adjustments"],
            "validation_adjustment_rows": artifacts["validation_adjustment_rows"],
            "summary": {
                "schema_version": REPORT_SCHEMA_VERSION,
                "passes_run": payload.get("passes_run", 0),
                "total_mutations": payload.get("total_mutations", 0),
                "rolled_back_passes": payload.get("rolled_back_passes", 0),
                "failed_passes": payload.get("failed_passes", 0),
                "discarded_mutations": payload.get("discarded_mutations", 0),
                "discarded_mutation_summary": artifacts["discarded_mutation_summary"],
                "discarded_mutation_priority": artifacts["discarded_mutation_priority"],
                "changed_bytes": aggregate_changed_bytes,
                "changed_regions": aggregate_regions,
                "structural_regions": aggregate_structural_regions,
                "structural_evidence": artifacts["structural_evidence"],
                "requested_validation_mode": payload.get(
                    "requested_validation_mode",
                    payload.get("validation_mode", "off"),
                ),
                "validation_mode": payload.get("validation_mode", "off"),
                "gate_evaluation": (
                    gate_evaluation.get("results", {})
                    if isinstance(gate_evaluation, dict)
                    else payload.get("summary", {}).get("gate_evaluation")
                ),
                "gate_failures": gate_failures,
                "gate_failure_priority": gate_failure_priority,
                "gate_failure_severity_priority": gate_failure_severity_priority,
                "degradation_roles": degradation_role_counts,
                "symbolic_issue_passes": enrichments["symbolic_issue_passes"],
                "symbolic_coverage_by_pass": enrichments["symbolic_coverage_by_pass"],
                "symbolic_severity_by_pass": enrichments["symbolic_severity_by_pass"],
                "symbolic_issue_map": enrichments["symbolic_issue_map"],
                "symbolic_coverage_map": enrichments["symbolic_coverage_map"],
                "symbolic_severity_map": enrichments["symbolic_severity_map"],
                "symbolic_status_counts": enrichments["symbolic_status_counts"],
                "symbolic_status_rows": enrichments["symbolic_status_rows"],
                "symbolic_status_map": enrichments["symbolic_status_map"],
                "symbolic_overview": artifacts["symbolic_overview"],
                "observable_mismatch_by_pass": enrichments["observable_mismatch_by_pass"],
                "observable_mismatch_map": enrichments["observable_mismatch_map"],
                "observable_mismatch_priority": enrichments["observable_mismatch_priority"],
                "pass_evidence": enrichments["pass_evidence"],
                "pass_evidence_priority": pass_evidence_priority,
                "pass_coverage_buckets": enrichments["pass_coverage_buckets"],
                "pass_risk_buckets": enrichments["pass_risk_buckets"],
                "pass_symbolic_summary": enrichments["pass_symbolic_summary"],
                "pass_validation_context": artifacts["pass_validation_context"],
                "validation_role_rows": artifacts["validation_role_rows"],
                "validation_role_map": artifacts["validation_role_map"],
                "pass_capabilities": artifacts["pass_capabilities"],
                "pass_capability_summary": artifacts["pass_capability_summary"],
                "pass_capability_summary_map": artifacts["pass_capability_summary_map"],
                "pass_evidence_map": artifacts["pass_evidence_map"],
                "pass_region_evidence_map": artifacts["pass_region_evidence_map"],
                "pass_triage_rows": artifacts["pass_triage_rows"],
                "pass_triage_map": artifacts["pass_triage_map"],
                "pass_evidence_compact": artifacts["pass_evidence_compact"],
                "normalized_pass_results": artifacts["normalized_pass_results"],
                "report_views": artifacts["report_views"],
                "pass_timing_summary": pass_timing_summary,
                "diff_digest": diff_digest,
                "support_profile": artifacts["support_profile"],
                "validation_adjustments": artifacts["validation_adjustments"],
                "validation_adjustment_rows": artifacts["validation_adjustment_rows"],
                "execution_time_seconds": payload.get("execution_time_seconds", 0.0),
            },
            "config": payload.get("config", {}),
            "support_matrix": PRODUCT_SUPPORT.to_dict(),
            "support_profile": artifacts["support_profile"],
            "validation_policy": payload.get("validation_policy"),
        }

    def save_report(self, output_path: str | Path, result: dict[str, Any] | None = None) -> Path:
        """Save a JSON report for the last engine run."""
        import json

        output = Path(output_path)
        report = self.build_report(result)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        logger.info(f"Saved engine report to: {output}")
        return output

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
