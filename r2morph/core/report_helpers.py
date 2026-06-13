"""Pure report-assembly helpers extracted from core/engine.py.

These are stateless dict/list -> dict/list functions that compute the
machine-readable engine report. They live in core/ (depending only on
core.constants) so that both core.engine (which re-exports them for
backward compatibility) and the reporting-layer ReportAssembler may use
them without any core -> reporting import (CLAUDE.md §7).
"""

from typing import Any

from r2morph.core.constants import SEVERITY_ORDER, UNKNOWN_SEVERITY_RANK
from r2morph.core.report_helpers_symbolic import _build_symbolic_summary_for_pass as _build_symbolic_summary_for_pass
from r2morph.core.report_helpers_symbolic import (
    _summarize_symbolic_coverage_by_pass as _summarize_symbolic_coverage_by_pass,
)
from r2morph.core.report_helpers_symbolic import _summarize_symbolic_issue_passes as _summarize_symbolic_issue_passes
from r2morph.core.report_helpers_symbolic import _summarize_symbolic_overview as _summarize_symbolic_overview
from r2morph.core.report_helpers_symbolic import (
    _summarize_symbolic_severity_by_pass as _summarize_symbolic_severity_by_pass,
)
from r2morph.core.report_helpers_symbolic import _summarize_symbolic_statuses as _summarize_symbolic_statuses
from r2morph.core.report_helpers_validation import (
    _build_pass_validation_context as _build_pass_validation_context,
)
from r2morph.core.report_helpers_validation import _build_validation_role_map as _build_validation_role_map
from r2morph.core.report_helpers_validation import _enrich_validation_policy as _enrich_validation_policy
from r2morph.core.report_helpers_validation import _summarize_degradation_roles as _summarize_degradation_roles
from r2morph.core.report_helpers_validation import (
    _summarize_validation_adjustment_rows as _summarize_validation_adjustment_rows,
)
from r2morph.core.report_helpers_validation import (
    _summarize_validation_adjustments as _summarize_validation_adjustments,
)
from r2morph.core.report_helpers_validation import _summarize_validation_role_rows as _summarize_validation_role_rows

REPORT_SCHEMA_VERSION = 1


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
    rows.sort(key=lambda item: (-item["execution_time_seconds"], item["pass_name"]))
    return rows


def _summarize_diff_digest(pass_results: dict[str, Any]) -> dict[str, Any]:
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
    rows: list[dict[str, Any]] = [
        {
            "pass_name": pass_name,
            "discarded_count": count,
            "impact_severity": min(
                (severity_by_reason.get(reason, "low") for reason in by_pass_reason.get(pass_name, {})),
                key=lambda severity: severity_order.get(severity, UNKNOWN_SEVERITY_RANK),
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
            severity_order.get(str(item.get("impact_severity", "low")), UNKNOWN_SEVERITY_RANK),
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
            severity_order.get(str(item.get("impact_severity", "low")), UNKNOWN_SEVERITY_RANK),
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
                "severity_order": severity_order.get(severity, UNKNOWN_SEVERITY_RANK),
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
            severity_order.get(item["severity"], UNKNOWN_SEVERITY_RANK),
            -item["symbolic_binary_mismatched_regions"],
            -item["structural_issue_count"],
            -item["changed_region_count"],
            item["pass_name"],
        )
    )
    return rows


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


def _build_pass_triage_map(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index triage rows by pass name."""
    return {str(row.get("pass_name")): dict(row) for row in rows if row.get("pass_name")}
