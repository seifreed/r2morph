"""
Command-line interface for r2morph.

Primary product flow:
    r2morph input.bin [output.bin]
    r2morph mutate input.bin -o output.bin --report report.json
"""

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from r2morph import __version__
from r2morph.core.config import EngineConfig
from r2morph.core.engine import (
    MorphEngine,
    _build_gate_failure_priority,
    _build_gate_failure_severity_priority,
    _summarize_gate_failures,
)
from r2morph.core.support import PRODUCT_SUPPORT, is_experimental_mutation, is_stable_mutation
from r2morph.utils.logging import setup_logging
from r2morph.validation import BinaryValidator
from r2morph.validation.validator import RuntimeComparisonConfig

app = typer.Typer(
    name="r2morph",
    help="Metamorphic mutation engine with structured validation and reporting",
    add_completion=False,
    invoke_without_command=True,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
experimental_app = typer.Typer(
    name="experimental",
    help="Secondary experimental commands outside the stable mutation engine surface",
    add_completion=False,
)
app.add_typer(experimental_app, name="experimental")
console = Console()

SUPPORTED_MUTATIONS = set(PRODUCT_SUPPORT.stable_mutations)
EXPERIMENTAL_MUTATIONS = set(PRODUCT_SUPPORT.experimental_mutations)
KNOWN_COMMANDS = {
    "analyze",
    "functions",
    "morph",
    "mutate",
    "validate",
    "diff",
    "report",
    "version",
    "cache",
}

SEVERITY_ORDER = {
    "mismatch": 0,
    "without-coverage": 1,
    "bounded-only": 2,
    "clean": 3,
    "not-requested": 4,
}


def _build_config(aggressive: bool, force: bool) -> EngineConfig:
    config = EngineConfig.create_aggressive() if aggressive else EngineConfig.create_default()
    if force:
        config.force_different = True
        config.nop.force_different = True
        config.substitution.force_different = True
        config.register.force_different = True
        config.expansion.force_different = True
        config.block.force_different = True
    return config


def _mutation_config(section: object, seed: int | None, offset: int) -> dict[str, object]:
    cfg = section.to_dict()
    if seed is not None:
        cfg["seed"] = seed + offset
    return cfg


def _warn_experimental_mutations(mutations: list[str]) -> None:
    if not mutations:
        return
    console.print(f"[yellow]Experimental mutations selected:[/yellow] {', '.join(mutations)}")
    console.print("[yellow]These passes are outside the stable core and validation coverage is best-effort.[/yellow]")


def _warn_experimental_validation_mode(validation_mode: str) -> None:
    if validation_mode != "symbolic":
        return
    console.print("[yellow]Experimental validation mode selected:[/yellow] symbolic")
    console.print(
        "[yellow]This mode performs bounded symbolic prechecks and structural fallback; it does not prove general semantic equivalence.[/yellow]"
    )


def _build_runtime_validator(
    *,
    timeout: int,
    corpus: Path | None = None,
    compare_files: bool = False,
    normalize_whitespace: bool = False,
) -> BinaryValidator:
    """Build a runtime validator from CLI options."""
    validator = BinaryValidator(
        timeout=timeout,
        comparison=RuntimeComparisonConfig(
            compare_files=compare_files,
            normalize_whitespace=normalize_whitespace,
        ),
    )
    if corpus is not None:
        with open(corpus, "r", encoding="utf-8") as handle:
            validator.load_test_cases(json.load(handle))
    return validator


def _load_binary_analyzer():
    """Lazy import for analysis-only flows outside the stable mutate/report path."""
    from r2morph.analysis.analyzer import BinaryAnalyzer

    return BinaryAnalyzer


def _load_diff_analyzer():
    """Lazy import for diff-only flows outside the stable mutate/report hot path."""
    from r2morph.analysis.diff_analyzer import DiffAnalyzer

    return DiffAnalyzer


def _load_mutation_pass_types() -> dict[str, type]:
    """Lazy import mutation passes so stable report/validate flows avoid extra imports."""
    from r2morph.mutations import (
        BlockReorderingPass,
        InstructionExpansionPass,
        InstructionSubstitutionPass,
        NopInsertionPass,
        RegisterSubstitutionPass,
    )

    return {
        "nop": NopInsertionPass,
        "substitute": InstructionSubstitutionPass,
        "register": RegisterSubstitutionPass,
        "expand": InstructionExpansionPass,
        "block": BlockReorderingPass,
    }


def _resolve_min_severity(min_severity: str | None) -> tuple[str | None, int | None]:
    """Validate and normalize a minimum severity option."""
    if min_severity is None:
        return None, None
    if min_severity not in SEVERITY_ORDER:
        console.print(f"[bold red]Error:[/bold red] Invalid --min-severity: {min_severity}")
        raise typer.Exit(2)
    return min_severity, SEVERITY_ORDER[min_severity]


def _resolve_report_context(
    *,
    payload: dict[str, Any],
    only_pass: str | None,
    only_pass_failure: str | None,
    only_expected_severity: str | None,
) -> dict[str, Any]:
    """Resolve the initial report context from payload and filters."""
    summary = payload.get("summary") or {}
    resolved_only_pass = _resolve_report_pass_filter(only_pass)
    resolved_only_pass_failure = _resolve_report_pass_filter(only_pass_failure)
    requested_validation_mode = summary.get(
        "requested_validation_mode",
        payload.get("requested_validation_mode", payload.get("validation_mode", "off")),
    )
    effective_validation_mode = summary.get(
        "validation_mode",
        payload.get("validation_mode", "off"),
    )
    validation_policy = payload.get("validation_policy")
    gate_evaluation = payload.get("gate_evaluation") or {}
    gate_requested = dict(gate_evaluation.get("requested", {}))
    gate_results = dict(gate_evaluation.get("results", {}))
    gate_failure_summary, gate_failure_priority, gate_failure_severity_priority, filtered_gate_failed = (
        _resolve_report_gate_state(
            summary=summary,
            payload=payload,
            gate_evaluation=gate_evaluation,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
        )
    )
    failed_gates = bool(gate_results) and not bool(gate_results.get("all_passed", True))
    if (only_expected_severity or resolved_only_pass_failure) and not gate_failure_summary.get(
        "require_pass_severity_failure_count", 0
    ):
        failed_gates = False
    if only_expected_severity or resolved_only_pass_failure:
        failed_gates = filtered_gate_failed
    degraded_validation = requested_validation_mode != effective_validation_mode
    degraded_passes = list((validation_policy or {}).get("limited_passes", []))
    degradation_roles = dict(summary.get("degradation_roles", {}))
    return {
        "summary": summary,
        "resolved_only_pass": resolved_only_pass,
        "resolved_only_pass_failure": resolved_only_pass_failure,
        "requested_validation_mode": requested_validation_mode,
        "effective_validation_mode": effective_validation_mode,
        "validation_policy": validation_policy,
        "gate_evaluation": gate_evaluation,
        "gate_requested": gate_requested,
        "gate_results": gate_results,
        "gate_failure_summary": gate_failure_summary,
        "gate_failure_priority": gate_failure_priority,
        "gate_failure_severity_priority": gate_failure_severity_priority,
        "failed_gates": failed_gates,
        "degraded_validation": degraded_validation,
        "degraded_passes": degraded_passes,
        "degradation_roles": degradation_roles,
    }


def _resolve_report_gate_state(
    *,
    summary: dict[str, Any],
    payload: dict[str, Any],
    gate_evaluation: dict[str, Any],
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Resolve persisted gate summaries and filtered gate state for report()."""
    gate_failure_summary = _summarize_gate_failures(gate_evaluation) if gate_evaluation else {}
    gate_failure_priority = list(summary.get("gate_failure_priority", payload.get("gate_failure_priority", [])))
    gate_failure_severity_priority = list(
        summary.get(
            "gate_failure_severity_priority",
            payload.get("gate_failure_severity_priority", []),
        )
    )
    gate_failure_summary, gate_failure_priority, gate_failure_severity_priority = _resolve_failed_gates_view(
        summary=summary,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
    )
    if gate_failure_summary.get("require_pass_severity_failures_by_pass"):
        ordered_failures = sorted(
            gate_failure_summary["require_pass_severity_failures_by_pass"].items(),
            key=lambda item: (
                min(_expected_severity_rank_from_failure(failure) for failure in item[1]),
                -len(item[1]),
                item[0],
            ),
        )
        gate_failure_summary["require_pass_severity_failures_by_pass"] = {
            pass_name: failures for pass_name, failures in ordered_failures
        }
    if not gate_failure_priority:
        gate_failure_priority = [
            {
                "pass_name": pass_name,
                "failure_count": len(failures),
                "strictest_expected_severity": min(
                    (
                        severity
                        for severity in (re.search(r"expected <= ([^)]+)", failure) for failure in failures)
                        if severity
                    ),
                    key=lambda match: _expected_severity_rank_from_failure(f"expected <= {match.group(1)}"),
                ).group(1)
                if failures
                else "unknown",
                "failures": list(failures),
            }
            for pass_name, failures in gate_failure_summary.get("require_pass_severity_failures_by_pass", {}).items()
        ]
    gate_failure_summary, gate_failure_priority, gate_failure_severity_priority, filtered_gate_failed = (
        _filter_failed_gates_view(
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
        )
    )
    return (
        gate_failure_summary,
        gate_failure_priority,
        gate_failure_severity_priority,
        filtered_gate_failed,
    )


def _emit_report_payload(
    *,
    filtered_payload: dict[str, Any],
    output: Path | None,
    summary_only: bool,
) -> None:
    """Write and/or print a filtered report payload."""
    if output is not None:
        output.write_text(json.dumps(filtered_payload, indent=2), encoding="utf-8")
        console.print(f"[cyan]Filtered report written:[/cyan] {output}")
    if not summary_only:
        console.print_json(json.dumps(filtered_payload))


def _enforce_report_requirements(
    *,
    require_results: bool,
    severity_rows: list[dict[str, Any]],
    min_severity_rank: int | None,
    mutation_count: int,
    only_failed_gates: bool,
    failed_gates: bool,
    gate_failure_count: int | None,
    only_risky_passes: bool,
    risky_pass_count: int,
    pass_count: int,
) -> None:
    """Apply report exit-code policy for empty views or missing severity."""
    severity_ok = _severity_threshold_met(severity_rows, min_severity_rank)
    has_results = _report_view_has_results(
        mutation_count=mutation_count,
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        gate_failure_count=gate_failure_count,
        only_risky_passes=only_risky_passes,
        risky_pass_count=risky_pass_count,
        pass_count=pass_count,
    )
    if require_results and (not has_results or not severity_ok):
        raise typer.Exit(1)


def _summarize_symbolic_view_from_mutations(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
) -> tuple[int, int, int, int, int, dict[str, dict[str, int]], list[tuple[str, int | None, int | None, list[str]]]]:
    """Resolve symbolic overview counters using summary first, mutation scan as fallback."""
    symbolic_overview = dict(summary.get("symbolic_overview", {}) or {})
    symbolic_requested = int(symbolic_overview.get("symbolic_requested", 0))
    observable_match = int(symbolic_overview.get("observable_match", 0))
    observable_mismatch = int(symbolic_overview.get("observable_mismatch", 0))
    observable_not_run = int(symbolic_overview.get("without_coverage", 0))
    bounded_only = int(symbolic_overview.get("bounded_only", 0))
    by_pass: dict[str, dict[str, int]] = {}
    mismatch_rows: list[tuple[str, int | None, int | None, list[str]]] = []

    for mutation in mutations:
        pass_name = mutation.get("pass_name", "unknown")
        pass_stats = by_pass.setdefault(
            pass_name,
            {
                "symbolic_requested": 0,
                "observable_match": 0,
                "observable_mismatch": 0,
                "bounded_only": 0,
                "without_coverage": 0,
            },
        )
        metadata = mutation.get("metadata", {})
        if not metadata.get("symbolic_requested"):
            continue
        if not symbolic_overview:
            symbolic_requested += 1
        pass_stats["symbolic_requested"] += 1
        if metadata.get("symbolic_observable_check_performed"):
            if metadata.get("symbolic_observable_equivalent"):
                if not symbolic_overview:
                    observable_match += 1
                pass_stats["observable_match"] += 1
            else:
                if not symbolic_overview:
                    observable_mismatch += 1
                pass_stats["observable_mismatch"] += 1
                mismatch_rows.append(
                    (
                        pass_name,
                        mutation.get("start_address"),
                        mutation.get("end_address"),
                        list(metadata.get("symbolic_observable_mismatches", [])),
                    )
                )
        elif metadata.get("symbolic_status") in {
            "bounded-step-passed",
            "bounded-step-known-equivalence",
            "bounded-step-observables-match",
            "bounded-step-observable-mismatch",
        }:
            if not symbolic_overview:
                bounded_only += 1
            pass_stats["bounded_only"] += 1
        else:
            if not symbolic_overview:
                observable_not_run += 1
            pass_stats["without_coverage"] += 1

    return (
        symbolic_requested,
        observable_match,
        observable_mismatch,
        bounded_only,
        observable_not_run,
        by_pass,
        mismatch_rows,
    )


def _severity_threshold_met(
    severity_rows: list[dict[str, object]],
    min_severity_rank: int | None,
) -> bool:
    """Return True when at least one severity row meets the requested threshold."""
    if min_severity_rank is None:
        return True
    if not severity_rows:
        return True
    return any(
        SEVERITY_ORDER.get(str(row.get("severity", "not-requested")), 99) <= min_severity_rank for row in severity_rows
    )


def _resolve_pass_severity_requirements(
    requirements: list[str] | None,
    *,
    alias_map: dict[str, str] | None = None,
) -> list[tuple[str, str, int]]:
    """Parse repeated PassName=severity requirements for mutate gating."""
    resolved: list[tuple[str, str, int]] = []
    aliases = {key.strip(): value for key, value in (alias_map or {}).items()}
    valid_pass_names = set(aliases.values())
    for item in requirements or []:
        if "=" not in item:
            console.print(
                f"[bold red]Error:[/bold red] Invalid --require-pass-severity: {item}. Expected PassName=severity"
            )
            raise typer.Exit(2)
        pass_name, severity = item.split("=", 1)
        pass_name = pass_name.strip()
        severity = severity.strip()
        pass_name = aliases.get(pass_name, pass_name)
        if not pass_name or severity not in SEVERITY_ORDER or (valid_pass_names and pass_name not in valid_pass_names):
            console.print(
                "[bold red]Error:[/bold red] "
                f"Invalid --require-pass-severity: {item}. "
                "Expected PassName=severity with severity in "
                "mismatch, without-coverage, bounded-only, clean, not-requested"
            )
            raise typer.Exit(2)
        resolved.append((pass_name, severity, SEVERITY_ORDER[severity]))
    return resolved


def _pass_severity_requirements_met(
    severity_rows: list[dict[str, object]],
    requirements: list[tuple[str, str, int]],
) -> tuple[bool, list[str]]:
    """Check whether all required passes meet their minimum allowed severity rank."""
    if not requirements:
        return True, []
    by_pass = {str(row.get("pass_name", "")): row for row in severity_rows}
    failures: list[str] = []
    for pass_name, severity, rank in requirements:
        row = by_pass.get(pass_name)
        if row is None:
            failures.append(f"{pass_name}=missing(expected <= {severity})")
            continue
        actual = str(row.get("severity", "not-requested"))
        actual_rank = SEVERITY_ORDER.get(actual, 99)
        if actual_rank > rank:
            failures.append(f"{pass_name}={actual}(expected <= {severity})")
    return not failures, failures


def _attach_gate_evaluation(
    report_payload: dict[str, object],
    *,
    min_severity: str | None,
    min_severity_passed: bool,
    require_pass_severity: list[tuple[str, str, int]],
    require_pass_severity_passed: bool,
    require_pass_severity_failures: list[str],
) -> dict[str, object]:
    """Attach CLI gate evaluation metadata to a report payload."""
    gate_evaluation = {
        "requested": {
            "min_severity": min_severity,
            "require_pass_severity": [
                {"pass_name": pass_name, "max_severity": severity}
                for pass_name, severity, _rank in require_pass_severity
            ],
        },
        "results": {
            "min_severity_passed": min_severity_passed,
            "require_pass_severity_passed": require_pass_severity_passed,
            "require_pass_severity_failures": list(require_pass_severity_failures),
            "all_passed": min_severity_passed and require_pass_severity_passed,
        },
    }
    gate_failures = _summarize_gate_failures(gate_evaluation)
    gate_failure_priority = _build_gate_failure_priority(gate_failures)
    gate_failure_severity_priority = _build_gate_failure_severity_priority(gate_failures)
    report_payload["gate_evaluation"] = gate_evaluation
    report_payload["gate_failures"] = gate_failures
    report_payload["gate_failure_priority"] = gate_failure_priority
    report_payload["gate_failure_severity_priority"] = gate_failure_severity_priority
    summary = dict(report_payload.get("summary", {}))
    summary["gate_evaluation"] = gate_evaluation["results"]
    summary["gate_failures"] = gate_failures
    summary["gate_failure_priority"] = gate_failure_priority
    summary["gate_failure_severity_priority"] = gate_failure_severity_priority
    report_payload["summary"] = summary
    return report_payload


def _report_view_has_results(
    *,
    mutation_count: int,
    only_failed_gates: bool,
    failed_gates: bool,
    gate_failure_count: int | None = None,
    only_risky_passes: bool = False,
    risky_pass_count: int | None = None,
    pass_count: int | None = None,
) -> bool:
    """Determine whether a filtered report view should count as non-empty."""
    if only_failed_gates:
        if gate_failure_count is not None:
            return gate_failure_count > 0
        return failed_gates
    if only_risky_passes and risky_pass_count is not None:
        return risky_pass_count > 0
    if pass_count is not None:
        return pass_count > 0
    return mutation_count > 0


def _gate_failure_result_count(gate_failures: dict[str, Any]) -> int:
    """Return a non-zero count when any persisted gate failure is present."""
    count = int(gate_failures.get("require_pass_severity_failure_count", 0) or 0)
    if gate_failures.get("min_severity_failed"):
        count += 1
    if gate_failures.get("all_passed") is False and count == 0:
        count = 1
    return count


def _sort_pass_evidence(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order pass evidence by risk priority for triage."""
    return sorted(
        (row for row in rows if row.get("pass_name")),
        key=lambda row: (
            -int(row.get("symbolic_binary_mismatched_regions", 0)),
            -int(row.get("structural_issue_count", 0)),
            -int(row.get("changed_region_count", 0)),
            -int(row.get("changed_bytes", 0)),
            str(row.get("pass_name", "")),
        ),
    )


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


def _visible_rows(
    rows: list[dict[str, Any]],
    visible_passes: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter row-shaped report data by visible pass names."""
    if not visible_passes:
        return [dict(row) for row in rows if row.get("pass_name")]
    return [dict(row) for row in rows if row.get("pass_name") and str(row.get("pass_name")) in visible_passes]


def _pass_names_from_triage_rows(
    triage_rows: list[dict[str, Any]],
    *,
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


def _resolve_pass_filter_sets(
    *,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
) -> dict[str, set[str]]:
    """Resolve pass filter buckets from persisted summary first, then fall back."""
    report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(report_views.get("general_renderer_state", {}) or {})
    pass_filter_views = dict(report_views.get("general_filter_views", report_views.get("pass_filter_views", {})) or {})
    if not pass_filter_views and general_renderer_state.get("general_filter_views"):
        pass_filter_views = {
            f"only_{key}_passes"
            if key in {"risky", "clean", "covered", "uncovered"}
            else "only_structural_risk"
            if key == "structural_risk"
            else "only_symbolic_risk"
            if key == "symbolic_risk"
            else key: value
            for key, value in dict(general_renderer_state.get("general_filter_views", {}) or {}).items()
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
        _summary_first(
            summary,
            "pass_risk_buckets",
            pass_filter_views or report_views.get("passes", {}),
        )
        or {}
    )
    coverage_buckets = dict(
        _summary_first(
            summary,
            "pass_coverage_buckets",
            {
                "covered": (pass_filter_views or report_views.get("passes", {})).get("covered", []),
                "uncovered": (pass_filter_views or report_views.get("passes", {})).get("uncovered", []),
                "clean_only": (pass_filter_views or report_views.get("passes", {})).get("clean", []),
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
        "symbolic": set(pass_filter_views.get("only_symbolic_risk", risk_buckets.get("symbolic", []))),
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
        "risky": lambda row, symbolic: _is_risky_pass(row, symbolic),
        "structural": lambda row, symbolic: _has_structural_risk(row),
        "symbolic": lambda row, symbolic: _has_symbolic_risk(row, symbolic),
        "clean": lambda row, symbolic: _is_clean_pass(row, symbolic),
        "covered": lambda row, symbolic: _is_covered_pass(row, symbolic),
        "uncovered": lambda row, symbolic: _is_uncovered_pass(row, symbolic),
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
            matches = {
                str(row.get("pass_name"))
                for row in summary_pass_evidence
                if row.get("pass_name")
                and predicate(
                    row,
                    pass_results.get(str(row.get("pass_name")), {}).get("symbolic_summary"),
                )
            }
        resolved[kind] = matches
    return resolved


def _resolve_mismatch_view(
    *,
    summary: dict[str, Any],
    filtered_mutations: list[dict[str, Any]],
) -> tuple[dict[str, int], dict[str, list[str]], list[dict[str, Any]]]:
    """Resolve mismatch counts/observables/priority from persisted summary first."""
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
    mismatch_view = list(only_mismatches_view.get("rows", report_views.get("mismatch_view", [])) or [])
    mismatch_compact_rows = list(only_mismatches_view.get("compact_rows", []) or [])
    if mismatch_map:
        counts_by_pass = {pass_name: int(row.get("mismatch_count", 0)) for pass_name, row in mismatch_map.items()}
        observables_by_pass = {pass_name: list(row.get("observables", [])) for pass_name, row in mismatch_map.items()}
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
    for mutation in filtered_mutations:
        pass_name = mutation.get("pass_name", "unknown")
        counts_by_pass[pass_name] = counts_by_pass.get(pass_name, 0) + 1
        mismatch_observables = mutation.get("metadata", {}).get("symbolic_observable_mismatches", [])
        if mismatch_observables:
            merged = set(observables_by_pass.get(pass_name, []))
            merged.update(mismatch_observables)
            observables_by_pass[pass_name] = sorted(merged)
    return counts_by_pass, observables_by_pass, mismatch_priority or mismatch_view


def _resolve_general_symbolic_state(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
    pass_results: dict[str, Any],
) -> dict[str, Any]:
    """Resolve symbolic summary inputs for the general report path."""
    (
        symbolic_requested,
        observable_match,
        observable_mismatch,
        bounded_only,
        observable_not_run,
        by_pass,
        mismatch_rows,
    ) = _summarize_symbolic_view_from_mutations(summary=summary, mutations=mutations)
    summary_normalized_pass_results = list(summary.get("normalized_pass_results", []) or [])
    return {
        "symbolic_requested": symbolic_requested,
        "observable_match": observable_match,
        "observable_mismatch": observable_mismatch,
        "bounded_only": bounded_only,
        "observable_not_run": observable_not_run,
        "by_pass": by_pass,
        "mismatch_rows": mismatch_rows,
        "summary_normalized_pass_results": summary_normalized_pass_results,
        "normalized_pass_map": _normalized_pass_map(summary_normalized_pass_results),
    }


def _resolve_general_report_flow_state(
    *,
    payload: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
    failed_gates: bool,
    validation_policy: dict[str, Any] | None,
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    resolved_only_pass: str | None,
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
) -> dict[str, Any]:
    """Resolve summary-first state for the general report path."""
    general_state = _resolve_general_report_state(
        summary=summary,
        payload=payload,
        pass_results=pass_results,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_risky_passes=only_risky_passes,
    )
    only_risky_filters = (
        only_risky_passes
        or only_structural_risk
        or only_symbolic_risk
        or only_uncovered_passes
        or only_covered_passes
        or only_clean_passes
    )
    mutations, adjusted_degraded_passes = _select_report_mutations(
        all_mutations=payload.get("mutations", []),
        degraded_validation=degraded_validation,
        failed_gates=failed_gates,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_filters=only_risky_filters,
        selected_risk_pass_names=general_state["selected_risk_pass_names"],
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        degraded_passes=degraded_passes,
    )
    symbolic_state = _resolve_general_symbolic_state(
        summary=summary,
        mutations=mutations,
        pass_results=pass_results,
    )
    filtered_summary, degradation_roles = _build_general_filtered_summary(
        summary=summary,
        mutations=mutations,
        pass_results=pass_results,
        pass_support=general_state["pass_support"],
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        degraded_passes=adjusted_degraded_passes,
        risky_pass_names=general_state["risky_pass_names"],
        structural_risk_pass_names=general_state["structural_risk_pass_names"],
        symbolic_risk_pass_names=general_state["symbolic_risk_pass_names"],
        covered_pass_names=general_state["covered_pass_names"],
        uncovered_pass_names=general_state["uncovered_pass_names"],
        clean_pass_names=general_state["clean_pass_names"],
        failed_gates=failed_gates,
        validation_policy=validation_policy,
        gate_evaluation=gate_evaluation,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        symbolic_requested=symbolic_state["symbolic_requested"],
        observable_match=symbolic_state["observable_match"],
        observable_mismatch=symbolic_state["observable_mismatch"],
        bounded_only=symbolic_state["bounded_only"],
        observable_not_run=symbolic_state["observable_not_run"],
        by_pass=symbolic_state["by_pass"],
        degradation_roles=dict(summary.get("degradation_roles", {})),
        normalized_pass_map=symbolic_state["normalized_pass_map"],
        selected_risk_pass_names=general_state["selected_risk_pass_names"],
        resolved_only_pass=resolved_only_pass,
        only_risky_filters=only_risky_filters,
        only_degraded=only_degraded,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_failed_gates=only_failed_gates,
    )
    return {
        **general_state,
        "only_risky_filters": only_risky_filters,
        "mutations": mutations,
        "degraded_passes": adjusted_degraded_passes,
        "symbolic_state": symbolic_state,
        "filtered_summary": filtered_summary,
        "degradation_roles": degradation_roles,
    }


def _resolve_only_mismatches_state(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
    filtered_summary: dict[str, Any],
    resolved_only_pass: str | None,
    degraded_passes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Resolve summary-first state for the `report --only-mismatches` path."""
    report_views = dict(summary.get("report_views", {}) or {})
    persisted_mismatch_view = dict(report_views.get("only_mismatches", {}) or {})
    filtered_mutations = [
        mutation
        for mutation in mutations
        if mutation.get("metadata", {}).get("symbolic_observable_check_performed")
        and not mutation.get("metadata", {}).get("symbolic_observable_equivalent", False)
    ]
    mismatch_counts_by_pass, mismatch_observables_by_pass, persisted_mismatch_priority = _resolve_mismatch_view(
        summary=summary, filtered_mutations=filtered_mutations
    )
    filtered_passes = sorted(
        {
            pass_name
            for pass_name, count in mismatch_counts_by_pass.items()
            if count > 0 and (resolved_only_pass is None or pass_name == resolved_only_pass)
        }
    )
    if not filtered_passes:
        filtered_passes = sorted(
            {
                str(row.get("pass_name"))
                for row in list(persisted_mismatch_view.get("compact_rows", []) or [])
                if row.get("pass_name") and (resolved_only_pass is None or row.get("pass_name") == resolved_only_pass)
            }
        )
    mismatch_pass_context = {}
    for pass_name in filtered_passes:
        context = filtered_summary["pass_validation_context"].get(pass_name)
        if context:
            mismatch_pass_context[pass_name] = context
    mismatch_degraded_passes = list(degraded_passes)
    if filtered_passes and mismatch_degraded_passes:
        mismatch_degraded_passes = [
            item
            for item in mismatch_degraded_passes
            if item.get("pass_name", item.get("mutation", "unknown")) in filtered_passes
        ]
    mismatch_severity_rows = _resolve_mismatch_severity_rows(
        summary=summary,
        filtered_summary=filtered_summary,
        filtered_passes=filtered_passes,
        mismatch_degraded_passes=mismatch_degraded_passes,
        mismatch_counts_by_pass=mismatch_counts_by_pass,
    )
    return {
        "filtered_mutations": filtered_mutations,
        "mismatch_counts_by_pass": mismatch_counts_by_pass,
        "mismatch_observables_by_pass": mismatch_observables_by_pass,
        "persisted_mismatch_priority": persisted_mismatch_priority,
        "filtered_passes": filtered_passes,
        "mismatch_pass_context": mismatch_pass_context,
        "mismatch_degraded_passes": mismatch_degraded_passes,
        "mismatch_severity_rows": mismatch_severity_rows,
    }


def _execute_only_mismatches_report_flow(
    *,
    payload: dict[str, Any],
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    mismatch_state: dict[str, Any],
    pass_support: dict[str, Any],
    requested_validation_mode: str,
    effective_validation_mode: str,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    failed_gates: bool,
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    min_severity: str | None,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
    validation_policy: dict[str, Any] | None,
    resolved_only_pass: str | None,
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    output: Path | None,
    summary_only: bool,
    require_results: bool,
    min_severity_rank: int | None,
) -> None:
    """Render and emit the `report --only-mismatches` path."""
    _render_only_mismatches_sections(
        filtered_mutations=mismatch_state["filtered_mutations"],
        filtered_passes=mismatch_state["filtered_passes"],
        mismatch_counts_by_pass=mismatch_state["mismatch_counts_by_pass"],
        mismatch_observables_by_pass=mismatch_state["mismatch_observables_by_pass"],
        mismatch_pass_context=mismatch_state["mismatch_pass_context"],
        mismatch_degraded_passes=mismatch_state["mismatch_degraded_passes"],
        degraded_passes=degraded_passes,
        degraded_validation=degraded_validation,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        mismatch_severity_rows=mismatch_state["mismatch_severity_rows"],
    )
    filtered_payload = _build_only_mismatches_payload(
        payload=payload,
        summary=summary,
        filtered_summary=filtered_summary,
        filtered_mutations=mismatch_state["filtered_mutations"],
        filtered_passes=mismatch_state["filtered_passes"],
        mismatch_counts_by_pass=mismatch_state["mismatch_counts_by_pass"],
        mismatch_observables_by_pass=mismatch_state["mismatch_observables_by_pass"],
        persisted_mismatch_priority=mismatch_state["persisted_mismatch_priority"],
        mismatch_severity_rows=mismatch_state["mismatch_severity_rows"],
        mismatch_pass_context=mismatch_state["mismatch_pass_context"],
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        mismatch_degraded_passes=mismatch_state["mismatch_degraded_passes"],
        degraded_passes=degraded_passes,
        degradation_roles=degradation_roles,
        failed_gates=failed_gates,
        pass_support=pass_support,
        gate_evaluation=gate_evaluation,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        min_severity=min_severity,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
        validation_policy=validation_policy,
    )
    filtered_payload["report_filters"] = _build_report_filters(
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_mismatches=True,
        min_severity=min_severity,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
    )
    _finalize_report_output(
        filtered_payload=filtered_payload,
        output=output,
        summary_only=summary_only,
        require_results=require_results,
        min_severity_rank=min_severity_rank,
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
    )


def _resolve_failed_gates_view(
    *,
    summary: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve failed-gates summary and ordering from persisted report views first."""
    report_views = dict(summary.get("report_views", {}) or {})
    failed_gates_view = dict(report_views.get("only_failed_gates", {}) or {})
    persisted_summary = dict(failed_gates_view.get("summary", {}) or {})
    persisted_priority = list(failed_gates_view.get("priority", []) or [])
    persisted_severity_priority = list(failed_gates_view.get("severity_priority", []) or [])
    if persisted_summary:
        gate_failure_summary = persisted_summary
    if persisted_priority:
        gate_failure_priority = persisted_priority
    if persisted_severity_priority:
        gate_failure_severity_priority = persisted_severity_priority
    if not gate_failure_severity_priority:
        gate_failure_severity_priority = _build_gate_failure_severity_priority(gate_failure_summary)
    return gate_failure_summary, gate_failure_priority, gate_failure_severity_priority


def _filter_failed_gates_view(
    *,
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Apply gate filters to the normalized failed-gates view."""
    filtered_summary = dict(gate_failure_summary)
    filtered_priority = list(gate_failure_priority)
    filtered_severity_priority = list(gate_failure_severity_priority)
    if only_expected_severity:
        filtered_severity_priority = [
            row for row in filtered_severity_priority if row.get("severity") == only_expected_severity
        ]
        filtered_priority = [
            row for row in filtered_priority if row.get("strictest_expected_severity") == only_expected_severity
        ]
        filtered_summary["require_pass_severity_failures_by_expected_severity"] = {
            row.get("severity", "unknown"): row.get("failure_count", 0) for row in filtered_severity_priority
        }
    if resolved_only_pass_failure:
        filtered_priority = [row for row in filtered_priority if row.get("pass_name") == resolved_only_pass_failure]
    filtered_summary["require_pass_severity_failures_by_pass"] = {
        row.get("pass_name", "unknown"): list(row.get("failures", [])) for row in filtered_priority
    }
    filtered_summary["require_pass_severity_failures"] = [
        failure for row in filtered_priority for failure in row.get("failures", [])
    ]
    filtered_summary["require_pass_severity_failure_count"] = len(filtered_summary["require_pass_severity_failures"])
    filtered_summary["require_pass_severity_failed"] = bool(filtered_summary["require_pass_severity_failures"])
    if resolved_only_pass_failure:
        severity_counts: dict[str, int] = {}
        for row in filtered_priority:
            severity = row.get("strictest_expected_severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + int(row.get("failure_count", 0))
        filtered_summary["require_pass_severity_failures_by_expected_severity"] = severity_counts
        filtered_severity_priority = _build_gate_failure_severity_priority(filtered_summary)
    filtered_failed = bool(filtered_summary.get("require_pass_severity_failure_count", 0))
    return filtered_summary, filtered_priority, filtered_severity_priority, filtered_failed


def _build_only_mismatches_filtered_summary(
    *,
    filtered_mutations: list[dict[str, Any]],
    filtered_passes: list[str],
    mismatch_counts_by_pass: dict[str, int],
    mismatch_observables_by_pass: dict[str, list[str]],
    persisted_mismatch_priority: list[dict[str, Any]],
    mismatch_severity_rows: list[dict[str, Any]],
    mismatch_pass_context: dict[str, Any],
    requested_validation_mode: str,
    effective_validation_mode: str,
    degraded_validation: bool,
    mismatch_degraded_passes: list[dict[str, Any]],
    degraded_passes: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    failed_gates: bool,
    pass_support: dict[str, Any],
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    min_severity: str | None,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
    validation_policy: dict[str, Any] | None,
    pass_region_evidence_map: dict[str, list[dict[str, Any]]] | None = None,
    mismatch_final_rows: list[dict[str, Any]] | None = None,
    mismatch_final_by_pass: dict[str, dict[str, Any]] | None = None,
    mismatch_compact_rows: list[dict[str, Any]] | None = None,
    mismatch_compact_by_pass: dict[str, dict[str, Any]] | None = None,
    mismatch_compact_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the filtered_summary payload for `report --only-mismatches`."""
    final_rows = list(mismatch_final_rows or [])
    compact_rows = list(mismatch_compact_rows or [])
    compact_by_pass = dict(mismatch_compact_by_pass or {})
    compact_summary = dict(mismatch_compact_summary or {})
    final_by_pass = dict(mismatch_final_by_pass or {})
    compact_row_by_pass = {str(row.get("pass_name")): dict(row) for row in compact_rows if row.get("pass_name")}
    if not final_rows and compact_rows:
        if final_by_pass:
            final_rows = [dict(final_by_pass[pass_name]) for pass_name in sorted(final_by_pass)]
        else:
            final_rows = [
                {
                    "pass_name": str(row.get("pass_name", "")),
                    "mismatch_count": int(row.get("mismatch_count", 0)),
                    "severity": row.get("severity", "mismatch"),
                    "role": row.get("role", "requested-mode"),
                    "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
                    "degraded_execution": bool(row.get("degraded_execution", False)),
                    "region_count": int(row.get("region_count", 0)),
                    "region_mismatch_count": int(row.get("region_mismatch_count", 0)),
                    "region_exit_match_count": int(row.get("region_exit_match_count", 0)),
                    "compact_region": dict(row.get("compact_region", {})),
                }
                for row in compact_rows
            ]
    elif final_rows:
        enriched_final_rows = []
        for row in final_rows:
            pass_name = str(row.get("pass_name", ""))
            compact_row = compact_row_by_pass.get(pass_name, {})
            enriched = dict(row)
            if "compact_region" not in enriched and compact_row.get("compact_region"):
                enriched["compact_region"] = dict(compact_row.get("compact_region", {}))
            enriched_final_rows.append(enriched)
        final_rows = enriched_final_rows
    if not compact_by_pass and compact_rows:
        compact_by_pass = {str(row.get("pass_name")): dict(row) for row in compact_rows if row.get("pass_name")}
    if not compact_summary:
        compact_summary = {
            "pass_count": len(compact_rows) or len(filtered_passes),
            "mismatch_count": sum(mismatch_counts_by_pass.values()),
            "degraded_pass_count": len([row for row in compact_rows if row.get("degraded_execution")]),
            "region_count": sum(int(row.get("region_count", 0)) for row in compact_rows),
            "region_mismatch_count": sum(int(row.get("region_mismatch_count", 0)) for row in compact_rows),
            "region_exit_match_count": sum(int(row.get("region_exit_match_count", 0)) for row in compact_rows),
            "passes": list(filtered_passes),
        }
    filtered_summary: dict[str, Any] = {
        "mutations": len(filtered_mutations),
        "passes": filtered_passes,
        "symbolic_requested": sum(
            1 for mutation in filtered_mutations if mutation.get("metadata", {}).get("symbolic_requested")
        ),
        "observable_match": 0,
        "observable_mismatch": len(filtered_mutations),
        "bounded_only": 0,
        "without_symbolic_coverage": 0,
        "symbolic_statuses": (
            {"bounded-step-observable-mismatch": len(filtered_mutations)} if filtered_mutations else {}
        ),
        "pass_capabilities": {
            pass_name: pass_support.get(pass_name, {}).get("validator_capabilities", {})
            for pass_name in filtered_passes
            if pass_support.get(pass_name)
        },
        "symbolic_severity_by_pass": mismatch_severity_rows,
        "mismatch_counts_by_pass": mismatch_counts_by_pass,
        "mismatch_observables_by_pass": mismatch_observables_by_pass,
        "observable_mismatch_priority": [
            dict(row) for row in persisted_mismatch_priority if row.get("pass_name") in filtered_passes
        ]
        or [
            {
                "pass_name": pass_name,
                "mismatch_count": mismatch_counts_by_pass.get(pass_name, 0),
                "observables": mismatch_observables_by_pass.get(pass_name, []),
            }
            for pass_name in filtered_passes
        ],
        "pass_validation_context": mismatch_pass_context,
        "pass_region_evidence_map": {
            pass_name: list((pass_region_evidence_map or {}).get(pass_name, []))
            for pass_name in filtered_passes
            if (pass_region_evidence_map or {}).get(pass_name)
        },
        "mismatch_compact_rows": compact_rows,
        "mismatch_compact_by_pass": compact_by_pass,
        "mismatch_compact_summary": compact_summary,
        "mismatch_final_rows": final_rows,
        "mismatch_final_by_pass": final_by_pass,
        "requested_validation_mode": requested_validation_mode,
        "validation_mode": effective_validation_mode,
        "degraded_validation": degraded_validation,
        "degraded_passes": mismatch_degraded_passes or degraded_passes,
        "degradation_roles": degradation_roles,
        "failed_gates": failed_gates,
    }
    if gate_evaluation:
        filtered_summary["gate_evaluation"] = gate_evaluation
        filtered_summary["gate_failures"] = gate_failure_summary
        filtered_summary["gate_failure_priority"] = gate_failure_priority
        filtered_summary["gate_failure_severity_priority"] = gate_failure_severity_priority
    if min_severity is not None:
        filtered_summary["min_severity"] = min_severity
    if only_expected_severity is not None:
        filtered_summary["only_expected_severity"] = only_expected_severity
    if resolved_only_pass_failure is not None:
        filtered_summary["only_pass_failure"] = resolved_only_pass_failure
    if validation_policy is not None:
        filtered_summary["validation_policy"] = validation_policy
    return filtered_summary


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
        console.print(f"[bold]Pass Filter Resolution[/bold]: {only_pass} -> {resolved_only_pass}")
    if only_pass_failure is not None and resolved_only_pass_failure != only_pass_failure:
        console.print(
            f"[bold]Pass Failure Filter Resolution[/bold]: {only_pass_failure} -> {resolved_only_pass_failure}"
        )
    if only_risky_passes:
        console.print(f"[bold]Risky Pass Filter[/bold]: {len(selected_risk_pass_names)} risky pass(es) detected")
    if only_uncovered_passes:
        console.print(
            f"[bold]Uncovered Pass Filter[/bold]: {len(selected_risk_pass_names)} uncovered pass(es) detected"
        )
    if only_covered_passes:
        console.print(f"[bold]Covered Pass Filter[/bold]: {len(selected_risk_pass_names)} covered pass(es) detected")
    if only_clean_passes:
        console.print(f"[bold]Clean Pass Filter[/bold]: {len(selected_risk_pass_names)} clean pass(es) detected")
    if only_structural_risk:
        console.print(
            f"[bold]Structural Risk Filter[/bold]: {len(selected_risk_pass_names)} structural-risk pass(es) detected"
        )
    if only_symbolic_risk:
        console.print(
            f"[bold]Symbolic Risk Filter[/bold]: {len(selected_risk_pass_names)} symbolic-risk pass(es) detected"
        )


def _build_general_report_payload(
    *,
    payload: dict[str, Any],
    mutations: list[dict[str, Any]],
    filtered_summary: dict[str, Any],
    resolved_only_pass: str | None,
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    min_severity: str | None,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
) -> dict[str, Any]:
    """Build the filtered payload for the general report path."""
    filtered_payload = dict(payload)
    filtered_payload["mutations"] = mutations
    filtered_payload["filtered_summary"] = filtered_summary
    report_filters = _build_report_filters(
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        min_severity=min_severity,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
    )
    if report_filters:
        filtered_payload["report_filters"] = report_filters
    if min_severity is not None:
        filtered_payload["filtered_summary"]["min_severity"] = min_severity
    if only_expected_severity is not None:
        filtered_payload["filtered_summary"]["only_expected_severity"] = only_expected_severity
    if resolved_only_pass_failure is not None:
        filtered_payload["filtered_summary"]["only_pass_failure"] = resolved_only_pass_failure
    return filtered_payload


def _finalize_report_output(
    *,
    filtered_payload: dict[str, Any],
    output: Path | None,
    summary_only: bool,
    require_results: bool,
    min_severity_rank: int | None,
    only_failed_gates: bool,
    failed_gates: bool,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
) -> None:
    """Emit a filtered report and enforce CLI exit policies."""
    filtered_summary = filtered_payload.get("filtered_summary", {})
    _emit_report_payload(
        filtered_payload=filtered_payload,
        output=output,
        summary_only=summary_only,
    )
    _enforce_report_requirements(
        require_results=require_results,
        severity_rows=filtered_summary.get("symbolic_severity_by_pass", []),
        min_severity_rank=min_severity_rank,
        mutation_count=len(filtered_payload.get("mutations", [])),
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        gate_failure_count=(
            int(filtered_summary.get("gate_failures", {}).get("require_pass_severity_failure_count", 0))
            if (only_expected_severity is not None or resolved_only_pass_failure is not None)
            else _gate_failure_result_count(filtered_summary.get("gate_failures", {}))
            if only_failed_gates
            else None
        ),
        only_risky_passes=(
            only_risky_passes
            or only_structural_risk
            or only_symbolic_risk
            or only_uncovered_passes
            or only_covered_passes
            or only_clean_passes
        ),
        risky_pass_count=(
            len(filtered_summary.get("passes", []))
            if (
                only_risky_passes
                or only_structural_risk
                or only_symbolic_risk
                or only_uncovered_passes
                or only_covered_passes
                or only_clean_passes
            )
            else len(filtered_summary.get("pass_evidence", []))
        ),
        pass_count=len(filtered_summary.get("passes", [])),
    )


def _resolve_mismatch_severity_rows(
    *,
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    filtered_passes: list[str],
    mismatch_degraded_passes: list[dict[str, Any]],
    mismatch_counts_by_pass: dict[str, int],
) -> list[dict[str, Any]]:
    """Resolve per-pass symbolic severity rows for only-mismatches."""
    mismatch_severity_rows = [
        row for row in list(summary.get("symbolic_severity_by_pass", [])) if row.get("pass_name") in filtered_passes
    ]
    if not mismatch_severity_rows and mismatch_degraded_passes:
        mismatch_severity_rows = [
            {
                "pass_name": item.get("pass_name", item.get("mutation", "unknown")),
                "severity": (
                    filtered_summary["pass_symbolic_summary"]
                    .get(item.get("pass_name", item.get("mutation", "unknown")), {})
                    .get("severity", "mismatch")
                ),
                "issue_count": (
                    filtered_summary["pass_symbolic_summary"]
                    .get(item.get("pass_name", item.get("mutation", "unknown")), {})
                    .get("issue_count", 0)
                ),
                "symbolic_requested": (
                    filtered_summary["pass_symbolic_summary"]
                    .get(item.get("pass_name", item.get("mutation", "unknown")), {})
                    .get("symbolic_requested", 0)
                ),
            }
            for item in mismatch_degraded_passes
        ]
    if not mismatch_severity_rows:
        mismatch_severity_rows = [
            {
                "pass_name": pass_name,
                "severity": (filtered_summary["pass_symbolic_summary"].get(pass_name, {}).get("severity", "mismatch")),
                "issue_count": mismatch_counts_by_pass.get(pass_name, 0),
                "symbolic_requested": mismatch_counts_by_pass.get(pass_name, 0),
            }
            for pass_name in filtered_passes
        ]
    return mismatch_severity_rows


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
    console.print(f"[bold]Filtered Mismatch Mutations[/bold]: {len(filtered_mutations)}")
    if degraded_validation:
        console.print(
            "[bold]Mismatch Degradation Context[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )
        if mismatch_degraded_passes:
            trigger_names = ", ".join(
                item.get("pass_name", item.get("mutation", "unknown")) for item in mismatch_degraded_passes
            )
            console.print(f"  trigger_passes={trigger_names}")
        elif degraded_passes:
            trigger_names = ", ".join(
                item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes
            )
            console.print(f"  trigger_passes={trigger_names}")
    if mismatch_counts_by_pass:
        console.print("[bold]Mismatch Pass Summary[/bold]:")
        for pass_name in filtered_passes:
            count = mismatch_counts_by_pass.get(pass_name, 0)
            role = mismatch_pass_context.get(pass_name, {}).get("role", "unknown")
            observables = mismatch_observables_by_pass.get(pass_name, [])
            observable_fragment = f", observables={','.join(observables)}" if observables else ""
            console.print(f"  [cyan]{pass_name}[/cyan]: mismatch_count={count}, role={role}{observable_fragment}")
    if mismatch_severity_rows:
        console.print("[bold]Mismatch Severity Priority[/bold]:")
        for row in mismatch_severity_rows:
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"severity={row.get('severity', 'unknown')}, "
                f"issue_count={row.get('issue_count', 0)}, "
                f"symbolic_requested={row.get('symbolic_requested', 0)}"
            )
    if filtered_mutations:
        console.print("[bold]Mismatch Addresses[/bold]:")
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
            console.print(f"  [cyan]{pass_name}[/cyan] @ {location}: {observable_str}")


def _build_only_mismatches_payload(
    *,
    payload: dict[str, Any],
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    filtered_mutations: list[dict[str, Any]],
    filtered_passes: list[str],
    mismatch_counts_by_pass: dict[str, int],
    mismatch_observables_by_pass: dict[str, list[str]],
    persisted_mismatch_priority: list[dict[str, Any]],
    mismatch_severity_rows: list[dict[str, Any]],
    mismatch_pass_context: dict[str, Any],
    requested_validation_mode: str,
    effective_validation_mode: str,
    degraded_validation: bool,
    mismatch_degraded_passes: list[dict[str, Any]],
    degraded_passes: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    failed_gates: bool,
    pass_support: dict[str, Any],
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    min_severity: str | None,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
    validation_policy: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build the filtered payload for report --only-mismatches."""
    mismatch_view = dict((dict(summary.get("report_views", {}) or {})).get("only_mismatches", {}) or {})
    filtered_payload = dict(payload)
    filtered_payload["mutations"] = filtered_mutations
    filtered_payload["filtered_summary"] = _build_only_mismatches_filtered_summary(
        filtered_mutations=filtered_mutations,
        filtered_passes=filtered_passes,
        mismatch_counts_by_pass=mismatch_counts_by_pass,
        mismatch_observables_by_pass=mismatch_observables_by_pass,
        persisted_mismatch_priority=persisted_mismatch_priority,
        mismatch_severity_rows=mismatch_severity_rows,
        mismatch_pass_context=mismatch_pass_context,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        mismatch_degraded_passes=mismatch_degraded_passes,
        degraded_passes=degraded_passes,
        degradation_roles=degradation_roles,
        failed_gates=failed_gates,
        pass_support=pass_support,
        gate_evaluation=gate_evaluation,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        min_severity=min_severity,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
        validation_policy=validation_policy,
        pass_region_evidence_map=filtered_summary.get("pass_region_evidence_map", {}),
        mismatch_final_rows=list(mismatch_view.get("final_rows", []) or []),
        mismatch_final_by_pass=dict(mismatch_view.get("final_by_pass", {}) or {}),
        mismatch_compact_rows=list(mismatch_view.get("compact_rows", []) or []),
        mismatch_compact_by_pass=dict(mismatch_view.get("compact_by_pass", {}) or {}),
        mismatch_compact_summary=dict(mismatch_view.get("compact_summary", {}) or {}),
    )
    return filtered_payload


def _render_pass_capabilities(
    *,
    filtered_summary: dict[str, Any],
) -> None:
    """Render pass capabilities for visible passes."""
    if not filtered_summary.get("pass_capabilities"):
        return
    console.print("[bold]Pass Capabilities[/bold]:")
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
            console.print(f"  [cyan]{pass_name}[/cyan]: " + ", ".join(fragments))


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
                    else "executed-under-degraded-mode"
                    if context.get("degraded_execution")
                    else "requested-mode"
                )
                filtered_summary.setdefault("pass_validation_context", {})[pass_name] = context
        if context:
            relevant_contexts.append((pass_name, context))
    if relevant_contexts:
        console.print("[bold]Pass Validation Context[/bold]:")
        for pass_name, context in relevant_contexts:
            _render_pass_validation_context(pass_name, context)


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
                    else "without-coverage"
                    if pass_stats["without_coverage"] > 0
                    else "bounded-only"
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
                    else "without-coverage"
                    if pass_stats["without_coverage"] > 0
                    else "bounded-only"
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


def _build_base_filtered_summary(
    *,
    mutations: list[dict[str, Any]],
    symbolic_requested: int,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    observable_not_run: int,
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
    risky_pass_names: set[str],
    structural_risk_pass_names: set[str],
    symbolic_risk_pass_names: set[str],
    covered_pass_names: set[str],
    uncovered_pass_names: set[str],
    clean_pass_names: set[str],
    failed_gates: bool,
    validation_policy: dict[str, Any] | None,
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the base filtered_summary payload used by general report views."""
    schema_version = summary.get("schema_version")
    resolved_general_views = _resolve_general_report_views(summary)
    summary_report_views = resolved_general_views["report_views"]
    general_renderer_state = resolved_general_views["general_renderer_state"]
    general_summary_rows = resolved_general_views["general_summary_rows"]
    general_summary_view = resolved_general_views["general_summary"]
    general_symbolic_view = resolved_general_views["general_symbolic"]
    general_gates_view = resolved_general_views["general_gates"]
    general_degradation_view = resolved_general_views["general_degradation"]
    general_discards_view = resolved_general_views["general_discards"]
    symbolic_overview = dict(general_symbolic_view.get("overview", {}) or {})
    general_summary_rows_by_section = {
        str(row.get("section")): dict(row) for row in general_summary_rows if row.get("section")
    }
    if not general_summary_view and general_renderer_state.get("summary"):
        general_summary_view = dict(general_renderer_state.get("summary", {}) or {})
    if not general_summary_view and general_summary_rows_by_section.get("passes"):
        general_summary_view = {
            key: value for key, value in general_summary_rows_by_section["passes"].items() if key != "section"
        }
    if not general_symbolic_view and general_renderer_state.get("symbolic"):
        general_symbolic_view = {"overview": dict(general_renderer_state.get("symbolic", {}) or {})}
    if not general_symbolic_view and general_summary_rows_by_section.get("symbolic"):
        general_symbolic_view = {
            "overview": {
                key: value for key, value in general_summary_rows_by_section["symbolic"].items() if key != "section"
            }
        }
    if not general_gates_view and general_renderer_state.get("gates"):
        general_gates_view = {"compact_summary": dict(general_renderer_state.get("gates", {}) or {})}
    if not general_gates_view and general_summary_rows_by_section.get("gates"):
        general_gates_view = {
            "compact_summary": {
                key: value for key, value in general_summary_rows_by_section["gates"].items() if key != "section"
            }
        }
    if not general_degradation_view and general_renderer_state.get("degradation"):
        general_degradation_view = {"summary": dict(general_renderer_state.get("degradation", {}) or {})}
    if not general_degradation_view and general_summary_rows_by_section.get("degradation"):
        general_degradation_view = {
            "summary": {
                key: value for key, value in general_summary_rows_by_section["degradation"].items() if key != "section"
            }
        }
    if not general_discards_view and general_renderer_state.get("discards"):
        general_discards_view = {"summary": dict(general_renderer_state.get("discards", {}) or {})}
    if not general_discards_view and general_summary_rows_by_section.get("discards"):
        general_discards_view = {
            "summary": {
                key: value for key, value in general_summary_rows_by_section["discards"].items() if key != "section"
            }
        }
    if not symbolic_overview and general_renderer_state.get("symbolic"):
        symbolic_overview = dict(general_renderer_state.get("symbolic", {}) or {})
    if not symbolic_overview and general_symbolic_view.get("overview"):
        symbolic_overview = dict(general_symbolic_view.get("overview", {}) or {})
    filtered_summary = {
        "schema_version": schema_version,
        "mutations": len(mutations),
        "passes": sorted({mutation.get("pass_name", "unknown") for mutation in mutations}),
        "symbolic_requested": int(symbolic_overview.get("symbolic_requested", symbolic_requested)),
        "observable_match": int(symbolic_overview.get("observable_match", observable_match)),
        "observable_mismatch": int(symbolic_overview.get("observable_mismatch", observable_mismatch)),
        "bounded_only": int(symbolic_overview.get("bounded_only", bounded_only)),
        "without_symbolic_coverage": int(symbolic_overview.get("without_coverage", observable_not_run)),
        "symbolic_issue_passes": [],
        "symbolic_coverage_by_pass": [],
        "symbolic_severity_by_pass": [],
        "symbolic_statuses": {},
        "pass_capabilities": {},
        "pass_validation_context": {},
        "pass_symbolic_summary": {},
        "pass_evidence": [],
        "pass_triage_rows": [],
        "normalized_pass_results": [],
        "pass_capability_summary": [],
        "validation_role_rows": [],
        "degradation_roles": {},
        "gate_failure_priority": list(gate_failure_priority),
        "gate_failure_severity_priority": list(gate_failure_severity_priority),
        "general_summary": general_summary_view,
        "general_summary_rows": general_summary_rows,
        "general_renderer_state": general_renderer_state,
        "general_symbolic": general_symbolic_view,
        "general_gates": general_gates_view,
        "general_degradation": general_degradation_view,
        "general_discards": general_discards_view,
        "general_filter_views": dict(summary_report_views.get("general_filter_views", {}) or {}),
        "general_triage_rows": list(summary_report_views.get("general_triage_rows", []) or []),
    }
    if not filtered_summary["general_filter_views"] and general_renderer_state.get("general_filter_views"):
        filtered_summary["general_filter_views"] = dict(general_renderer_state.get("general_filter_views", {}) or {})
    if not filtered_summary["general_filter_views"] and general_renderer_state.get("filter_views"):
        filtered_summary["general_filter_views"] = dict(general_renderer_state.get("filter_views", {}) or {})
    if not filtered_summary["general_triage_rows"] and general_renderer_state.get("general_triage_rows"):
        filtered_summary["general_triage_rows"] = list(general_renderer_state.get("general_triage_rows", []) or [])
    if not filtered_summary["general_triage_rows"] and general_renderer_state.get("triage_rows"):
        filtered_summary["general_triage_rows"] = list(general_renderer_state.get("triage_rows", []) or [])
    filtered_summary.update(
        _build_filtered_summary_risk_coverage_sections(
            summary=summary,
            risky_pass_names=risky_pass_names,
            structural_risk_pass_names=structural_risk_pass_names,
            symbolic_risk_pass_names=symbolic_risk_pass_names,
            covered_pass_names=covered_pass_names,
            uncovered_pass_names=uncovered_pass_names,
            clean_pass_names=clean_pass_names,
        )
    )
    filtered_summary.update(
        _build_filtered_summary_degradation_sections(
            summary=summary,
            validation_policy=validation_policy,
            requested_validation_mode=requested_validation_mode,
            effective_validation_mode=effective_validation_mode,
            degraded_validation=degraded_validation,
            degraded_passes=degraded_passes,
        )
    )
    filtered_summary.update(
        _build_filtered_summary_gate_sections(
            summary=summary,
            gate_evaluation=gate_evaluation,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            failed_gates=failed_gates,
        )
    )
    summary_symbolic_status_counts = dict(summary.get("symbolic_status_counts", {}) or {})
    if summary_symbolic_status_counts:
        filtered_summary["symbolic_statuses"] = dict(summary_symbolic_status_counts)
    else:
        for mutation in mutations:
            status = mutation.get("metadata", {}).get("symbolic_status")
            if not status:
                continue
            filtered_summary["symbolic_statuses"][status] = filtered_summary["symbolic_statuses"].get(status, 0) + 1
    return filtered_summary


def _resolve_general_report_views(summary: dict[str, Any]) -> dict[str, Any]:
    """Resolve summary-first general report views with renderer-state fallbacks."""
    summary_report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(summary_report_views.get("general_renderer_state", {}) or {})
    general_summary_view = dict(summary_report_views.get("general_summary", {}) or {})
    general_symbolic_view = dict(summary_report_views.get("general_symbolic", {}) or {})
    general_gates_view = dict(summary_report_views.get("general_gates", {}) or {})
    general_degradation_view = dict(summary_report_views.get("general_degradation", {}) or {})
    general_discards_view = dict(summary_report_views.get("general_discards", {}) or {})
    general_summary_rows = list(summary_report_views.get("general_summary_rows", []) or [])

    if not general_summary_rows and general_renderer_state.get("general_summary_rows"):
        general_summary_rows = list(general_renderer_state.get("general_summary_rows", []) or [])
    if not general_summary_rows and general_renderer_state.get("summary_rows"):
        general_summary_rows = list(general_renderer_state.get("summary_rows", []) or [])
    if not general_summary_view and general_renderer_state.get("general_summary"):
        general_summary_view = dict(general_renderer_state.get("general_summary", {}) or {})
    if not general_symbolic_view and general_renderer_state.get("general_symbolic"):
        general_symbolic_view = {"overview": dict(general_renderer_state.get("general_symbolic", {}) or {})}
    if not general_gates_view and general_renderer_state.get("general_gates"):
        general_gates_view = {"compact_summary": dict(general_renderer_state.get("general_gates", {}) or {})}
    if not general_degradation_view and general_renderer_state.get("general_degradation"):
        general_degradation_view = {"summary": dict(general_renderer_state.get("general_degradation", {}) or {})}
    if not general_discards_view and general_renderer_state.get("general_discards"):
        general_discards_view = {"summary": dict(general_renderer_state.get("general_discards", {}) or {})}

    return {
        "report_views": summary_report_views,
        "general_renderer_state": general_renderer_state,
        "general_summary_rows": general_summary_rows,
        "general_summary": general_summary_view,
        "general_symbolic": general_symbolic_view,
        "general_gates": general_gates_view,
        "general_degradation": general_degradation_view,
        "general_discards": general_discards_view,
    }


def _build_filtered_summary_gate_sections(
    *,
    summary: dict[str, Any],
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    failed_gates: bool,
) -> dict[str, Any]:
    """Build filtered_summary gate-related sections from persisted report views first."""
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    general_gates = resolved_general_views["general_gates"]
    persisted_view = dict(report_views.get("only_failed_gates", {}) or {})
    summary_payload = dict(
        persisted_view.get("summary", {})
        or general_gates.get("summary", {})
        or gate_failure_summary
        or general_gates.get("compact_summary", {})
    )
    priority_payload = list(persisted_view.get("priority", []) or gate_failure_priority)
    severity_payload = list(
        persisted_view.get("severity_priority", [])
        or general_gates.get("severity_priority", [])
        or gate_failure_severity_priority
    )
    compact_summary = dict(persisted_view.get("compact_summary", {}) or general_gates.get("compact_summary", {}) or {})
    final_rows = list(persisted_view.get("final_rows", []) or [])
    compact_rows = list(persisted_view.get("compact_rows", []) or [])
    final_by_pass = dict(persisted_view.get("final_by_pass", {}) or {})
    if not final_rows and priority_payload:
        if final_by_pass:
            final_rows = [dict(final_by_pass[pass_name]) for pass_name in sorted(final_by_pass)]
        else:
            final_rows = [
                {
                    "pass_name": str(row.get("pass_name", "")),
                    "failure_count": int(row.get("failure_count", 0)),
                    "strictest_expected_severity": row.get("strictest_expected_severity", "unknown"),
                    "role": row.get("role", "requested-mode"),
                    "failed": bool(row.get("failures")),
                    "failures": list(row.get("failures", [])),
                }
                for row in priority_payload
                if row.get("pass_name")
            ]
    elif final_rows:
        priority_by_pass = {
            str(row.get("pass_name", "")): dict(row) for row in priority_payload if row.get("pass_name")
        }
        enriched_final_rows = []
        for row in final_rows:
            pass_name = str(row.get("pass_name", ""))
            priority_row = priority_by_pass.get(pass_name, {})
            enriched = dict(row)
            if "failures" not in enriched and priority_row.get("failures") is not None:
                enriched["failures"] = list(priority_row.get("failures", []))
            enriched_final_rows.append(enriched)
        final_rows = enriched_final_rows
    if not compact_summary:
        compact_summary = {
            "failed": bool(persisted_view.get("failed", False) or failed_gates),
            "failure_count": int(
                persisted_view.get("failure_count", 0) or summary_payload.get("require_pass_severity_failure_count", 0)
            ),
            "pass_count": int(persisted_view.get("pass_count", 0)),
            "expected_severity_counts": dict(persisted_view.get("expected_severity_counts", {}) or {}),
            "severity_priority": severity_payload,
            "passes": list(persisted_view.get("passes", []) or []),
        }
    section: dict[str, Any] = {
        "failed_gates": failed_gates or bool(persisted_view.get("failed", False)),
        "gate_failure_priority": priority_payload,
        "gate_failure_severity_priority": severity_payload,
        "gate_failure_final_rows": final_rows,
        "gate_failure_final_by_pass": final_by_pass,
        "gate_failure_compact_rows": compact_rows,
        "gate_failure_compact_by_pass": dict(persisted_view.get("compact_by_pass", {}) or {}),
        "gate_failure_compact_summary": compact_summary,
    }
    if gate_evaluation:
        section["gate_evaluation"] = gate_evaluation
    if summary_payload:
        section["gate_failures"] = summary_payload
    return section


def _build_filtered_summary_degradation_sections(
    *,
    summary: dict[str, Any],
    validation_policy: dict[str, Any] | None,
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build filtered_summary degradation/validation-mode sections."""
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    validation_adjustments = dict(summary.get("validation_adjustments", {}) or {})
    general_degradation = resolved_general_views["general_degradation"]
    persisted_adjustments = dict(report_views.get("validation_adjustments", {}) or {})
    degradation_roles = dict(summary.get("degradation_roles", {}) or {})
    section: dict[str, Any] = {
        "requested_validation_mode": requested_validation_mode,
        "validation_mode": effective_validation_mode,
        "degraded_validation": degraded_validation,
        "degraded_passes": degraded_passes,
        "degradation_roles": degradation_roles,
    }
    if validation_policy is not None:
        section["validation_policy"] = validation_policy
    if general_degradation.get("summary"):
        section["validation_adjustments"] = dict(general_degradation.get("summary", {}))
    elif validation_adjustments:
        section["validation_adjustments"] = validation_adjustments
    if persisted_adjustments:
        if persisted_adjustments.get("by_pass"):
            section["validation_adjustment_by_pass"] = dict(persisted_adjustments.get("by_pass", {}))
        if persisted_adjustments.get("compact_by_pass"):
            section["validation_adjustment_compact_by_pass"] = dict(persisted_adjustments.get("compact_by_pass", {}))
        if persisted_adjustments.get("rows"):
            section["validation_adjustment_rows"] = list(persisted_adjustments.get("rows", []))
        if persisted_adjustments.get("compact_rows"):
            section["validation_adjustment_compact_rows"] = list(persisted_adjustments.get("compact_rows", []))
        if persisted_adjustments.get("summary"):
            section["validation_adjustment_summary"] = dict(persisted_adjustments.get("summary", {}))
        if persisted_adjustments.get("compact_summary"):
            section["validation_adjustment_compact_summary"] = dict(persisted_adjustments.get("compact_summary", {}))
        elif persisted_adjustments.get("summary"):
            section["validation_adjustment_compact_summary"] = dict(persisted_adjustments.get("summary", {}))
    elif general_degradation:
        if general_degradation.get("rows"):
            section["validation_adjustment_rows"] = list(general_degradation.get("rows", []))
        if general_degradation.get("compact_rows"):
            section["validation_adjustment_compact_rows"] = list(general_degradation.get("compact_rows", []))
        if general_degradation.get("summary"):
            section["validation_adjustment_summary"] = dict(general_degradation.get("summary", {}))
            section["validation_adjustment_compact_summary"] = dict(general_degradation.get("summary", {}))
    elif validation_adjustments:
        section["validation_adjustment_compact_summary"] = {
            "requested_validation_mode": requested_validation_mode,
            "effective_validation_mode": effective_validation_mode,
            "degraded_validation": degraded_validation,
        }
    return section


def _build_filtered_summary_risk_coverage_sections(
    *,
    summary: dict[str, Any],
    risky_pass_names: set[str],
    structural_risk_pass_names: set[str],
    symbolic_risk_pass_names: set[str],
    covered_pass_names: set[str],
    uncovered_pass_names: set[str],
    clean_pass_names: set[str],
) -> dict[str, Any]:
    """Build filtered_summary risk/coverage sections from persisted summary first."""
    report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(report_views.get("general_renderer_state", {}) or {})
    pass_risk_buckets = dict(_summary_first(summary, "pass_risk_buckets", {}) or {})
    pass_coverage_buckets = dict(_summary_first(summary, "pass_coverage_buckets", {}) or {})
    general_filter_views = dict(report_views.get("general_filter_views", {}) or {})
    if not general_filter_views and general_renderer_state.get("general_filter_views"):
        general_filter_views = dict(general_renderer_state.get("general_filter_views", {}) or {})
    if not general_filter_views and general_renderer_state.get("filter_views"):
        general_filter_views = dict(general_renderer_state.get("filter_views", {}) or {})
    risky = sorted(pass_risk_buckets.get("risky", list(risky_pass_names)) or list(risky_pass_names))
    if not risky and general_filter_views.get("risky"):
        risky = sorted(str(name) for name in general_filter_views.get("risky", []) if name)
    structural = sorted(
        pass_risk_buckets.get("structural", list(structural_risk_pass_names)) or list(structural_risk_pass_names)
    )
    if not structural and general_filter_views.get("structural_risk"):
        structural = sorted(str(name) for name in general_filter_views.get("structural_risk", []) if name)
    symbolic = sorted(
        pass_risk_buckets.get("symbolic", list(symbolic_risk_pass_names)) or list(symbolic_risk_pass_names)
    )
    if not symbolic and general_filter_views.get("symbolic_risk"):
        symbolic = sorted(str(name) for name in general_filter_views.get("symbolic_risk", []) if name)
    clean = sorted(pass_risk_buckets.get("clean", list(clean_pass_names)) or list(clean_pass_names))
    if not clean and general_filter_views.get("clean"):
        clean = sorted(str(name) for name in general_filter_views.get("clean", []) if name)
    covered = sorted(pass_coverage_buckets.get("covered", list(covered_pass_names)) or list(covered_pass_names))
    if not covered and general_filter_views.get("covered"):
        covered = sorted(str(name) for name in general_filter_views.get("covered", []) if name)
    uncovered = sorted(pass_coverage_buckets.get("uncovered", list(uncovered_pass_names)) or list(uncovered_pass_names))
    if not uncovered and general_filter_views.get("uncovered"):
        uncovered = sorted(str(name) for name in general_filter_views.get("uncovered", []) if name)
    clean_only = sorted(pass_coverage_buckets.get("clean_only", list(clean_pass_names)) or list(clean_pass_names))
    return {
        "pass_coverage_buckets": {
            "covered": covered,
            "uncovered": uncovered,
            "clean_only": clean_only,
        },
        "pass_risk_buckets": {
            "risky": risky,
            "structural": structural,
            "symbolic": symbolic,
            "clean": clean,
            "covered": covered,
            "uncovered": uncovered,
        },
        "risky_passes": risky,
        "structural_risk_passes": structural,
        "symbolic_risk_passes": symbolic,
        "covered_passes": covered,
        "uncovered_passes": uncovered,
        "clean_passes": clean,
    }


def _build_general_filtered_summary(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
    pass_results: dict[str, Any],
    pass_support: dict[str, Any],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
    risky_pass_names: set[str],
    structural_risk_pass_names: set[str],
    symbolic_risk_pass_names: set[str],
    covered_pass_names: set[str],
    uncovered_pass_names: set[str],
    clean_pass_names: set[str],
    failed_gates: bool,
    validation_policy: dict[str, Any] | None,
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    symbolic_requested: int,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    observable_not_run: int,
    by_pass: dict[str, dict[str, int]],
    degradation_roles: dict[str, int],
    normalized_pass_map: dict[str, dict[str, Any]],
    selected_risk_pass_names: set[str],
    resolved_only_pass: str | None,
    only_risky_filters: bool,
    only_degraded: bool,
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_failed_gates: bool,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Build the general filtered_summary payload for report()."""
    filtered_summary = _build_base_filtered_summary(
        mutations=mutations,
        symbolic_requested=symbolic_requested,
        observable_match=observable_match,
        observable_mismatch=observable_mismatch,
        bounded_only=bounded_only,
        observable_not_run=observable_not_run,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        degraded_passes=degraded_passes,
        risky_pass_names=risky_pass_names,
        structural_risk_pass_names=structural_risk_pass_names,
        symbolic_risk_pass_names=symbolic_risk_pass_names,
        covered_pass_names=covered_pass_names,
        uncovered_pass_names=uncovered_pass_names,
        clean_pass_names=clean_pass_names,
        failed_gates=failed_gates,
        validation_policy=validation_policy,
        gate_evaluation=gate_evaluation,
        gate_failure_summary=gate_failure_summary,
        summary=summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
    )
    summary_report_views = dict(summary.get("report_views", {}) or {})
    only_pass_view = dict(summary_report_views.get("only_pass", {}) or {})
    summary_general_passes = list(summary_report_views.get("general_passes", []) or [])
    summary_general_pass_rows = list(summary_report_views.get("general_pass_rows", []) or [])
    general_renderer_state = dict(summary_report_views.get("general_renderer_state", {}) or {})
    if not summary_general_pass_rows and general_renderer_state.get("general_pass_rows"):
        summary_general_pass_rows = list(general_renderer_state.get("general_pass_rows", []) or [])
    if not summary_general_passes and summary_general_pass_rows:
        summary_general_passes = list(summary_general_pass_rows)
    summary_general_summary = dict(summary_report_views.get("general_summary", {}) or {})
    if not summary_general_summary:
        summary_general_summary = dict(filtered_summary.get("general_summary", {}) or {})
    filtered_summary["passes"] = _resolve_general_filtered_passes(
        existing_passes=filtered_summary["passes"],
        summary_only_pass_view=only_pass_view,
        summary_general_passes=summary_general_passes,
        summary_general_pass_rows=summary_general_pass_rows,
        summary_general_summary=summary_general_summary,
        resolved_only_pass=resolved_only_pass,
        selected_risk_pass_names=selected_risk_pass_names,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_failed_gates=only_failed_gates,
        gate_failure_priority=gate_failure_priority,
    )
    degradation_roles = _populate_filtered_summary_pass_sections(
        filtered_summary=filtered_summary,
        summary=summary,
        pass_results=pass_results,
        pass_support=pass_support,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_passes=degraded_passes,
        degradation_roles=degradation_roles,
        by_pass=by_pass,
        normalized_pass_map=normalized_pass_map,
        selected_risk_pass_names=selected_risk_pass_names,
        resolved_only_pass=resolved_only_pass,
        only_risky_filters=only_risky_filters,
        only_degraded=only_degraded,
    )
    return filtered_summary, degradation_roles


def _resolve_general_filtered_passes(
    *,
    existing_passes: list[str],
    summary_only_pass_view: dict[str, Any],
    summary_general_passes: list[dict[str, Any]],
    summary_general_pass_rows: list[dict[str, Any]],
    summary_general_summary: dict[str, Any],
    resolved_only_pass: str | None,
    selected_risk_pass_names: set[str],
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_failed_gates: bool,
    gate_failure_priority: list[dict[str, Any]],
) -> list[str]:
    """Resolve the visible pass list for the general report path."""
    resolved_passes = list(existing_passes)
    if not resolved_passes and summary_general_summary.get("passes"):
        resolved_passes = [str(pass_name) for pass_name in list(summary_general_summary.get("passes", [])) if pass_name]
    if not resolved_passes and summary_general_passes:
        resolved_passes = sorted({str(row.get("pass_name")) for row in summary_general_passes if row.get("pass_name")})
    if not resolved_passes and summary_general_pass_rows:
        resolved_passes = sorted(
            {str(row.get("pass_name")) for row in summary_general_pass_rows if row.get("pass_name")}
        )
    if resolved_only_pass and not resolved_passes and resolved_only_pass in summary_only_pass_view:
        resolved_passes = [resolved_only_pass]
    if (
        only_risky_passes
        or only_structural_risk
        or only_symbolic_risk
        or only_uncovered_passes
        or only_covered_passes
        or only_clean_passes
    ):
        return sorted(
            pass_name
            for pass_name in selected_risk_pass_names
            if resolved_only_pass is None or pass_name == resolved_only_pass
        )
    if resolved_only_pass and not resolved_passes:
        return [resolved_only_pass]
    if only_failed_gates and not resolved_passes and gate_failure_priority:
        return sorted({str(row.get("pass_name")) for row in gate_failure_priority if row.get("pass_name")})
    return resolved_passes


def _resolve_general_report_state(
    *,
    summary: dict[str, Any],
    payload: dict[str, Any],
    pass_results: dict[str, Any],
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_risky_passes: bool,
) -> dict[str, Any]:
    """Resolve summary-first pass filter state for the general report path."""
    pass_support = payload.get("pass_support", {})
    pass_filter_sets = _resolve_pass_filter_sets(summary=summary, pass_results=pass_results)
    risky_pass_names = set(pass_filter_sets["risky"])
    structural_risk_pass_names = set(pass_filter_sets["structural"])
    symbolic_risk_pass_names = set(pass_filter_sets["symbolic"])
    clean_pass_names = set(pass_filter_sets["clean"])
    covered_pass_names = set(pass_filter_sets["covered"])
    uncovered_pass_names = set(pass_filter_sets["uncovered"])
    selected_risk_pass_names = set(risky_pass_names)
    if only_uncovered_passes:
        selected_risk_pass_names = uncovered_pass_names
    elif only_covered_passes:
        selected_risk_pass_names = covered_pass_names
    elif only_clean_passes:
        selected_risk_pass_names = clean_pass_names
    elif only_structural_risk and only_symbolic_risk:
        selected_risk_pass_names = structural_risk_pass_names & symbolic_risk_pass_names
    elif only_structural_risk:
        selected_risk_pass_names = structural_risk_pass_names
    elif only_symbolic_risk:
        selected_risk_pass_names = symbolic_risk_pass_names
    elif only_risky_passes:
        selected_risk_pass_names = risky_pass_names
    return {
        "pass_support": pass_support,
        "risky_pass_names": risky_pass_names,
        "structural_risk_pass_names": structural_risk_pass_names,
        "symbolic_risk_pass_names": symbolic_risk_pass_names,
        "clean_pass_names": clean_pass_names,
        "covered_pass_names": covered_pass_names,
        "uncovered_pass_names": uncovered_pass_names,
        "selected_risk_pass_names": selected_risk_pass_names,
    }


def _select_report_mutations(
    *,
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
    """Apply report filters to mutations and degraded pass rows."""
    mutations = list(all_mutations)
    adjusted_degraded_passes = list(degraded_passes)
    if only_degraded and not degraded_validation:
        mutations = []
    if only_failed_gates and not failed_gates:
        mutations = []
    if only_risky_filters:
        mutations = [mutation for mutation in mutations if mutation.get("pass_name") in selected_risk_pass_names]
    if resolved_only_pass and adjusted_degraded_passes:
        adjusted_degraded_passes = [
            item
            for item in adjusted_degraded_passes
            if item.get("pass_name") == resolved_only_pass or item.get("mutation") == resolved_only_pass
        ]
    if only_risky_filters and adjusted_degraded_passes:
        adjusted_degraded_passes = [
            item
            for item in adjusted_degraded_passes
            if item.get("pass_name", item.get("mutation", "unknown")) in selected_risk_pass_names
        ]
    if resolved_only_pass:
        mutations = [mutation for mutation in mutations if mutation.get("pass_name") == resolved_only_pass]
    if only_status:
        mutations = [
            mutation for mutation in mutations if mutation.get("metadata", {}).get("symbolic_status") == only_status
        ]
    return mutations, adjusted_degraded_passes


def _populate_filtered_summary_pass_sections(
    *,
    filtered_summary: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    pass_support: dict[str, Any],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_passes: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    by_pass: dict[str, dict[str, int]],
    normalized_pass_map: dict[str, dict[str, Any]],
    selected_risk_pass_names: set[str],
    resolved_only_pass: str | None,
    only_risky_filters: bool,
    only_degraded: bool,
) -> dict[str, int]:
    """Populate filtered_summary pass-related sections using summary-first data."""
    summary_sources = _resolve_summary_pass_sources(summary)
    summary_pass_validation_context = summary_sources["pass_validation_context"]
    summary_pass_symbolic_summary = summary_sources["pass_symbolic_summary"]
    summary_pass_capabilities = summary_sources["pass_capabilities"]
    summary_pass_evidence_map = summary_sources["pass_evidence_map"]
    summary_pass_region_evidence_map = summary_sources["pass_region_evidence_map"]
    summary_pass_triage_map = summary_sources["pass_triage_map"]
    summary_normalized_pass_results = summary_sources["normalized_pass_results"]
    summary_symbolic_issue_map = summary_sources["symbolic_issue_map"]
    summary_symbolic_coverage_map = summary_sources["symbolic_coverage_map"]
    summary_symbolic_severity_map = summary_sources["symbolic_severity_map"]
    summary_pass_capability_summary_map = summary_sources["pass_capability_summary_map"]
    summary_validation_role_map = summary_sources["validation_role_map"]
    summary_discarded_mutation_summary = summary_sources["discarded_mutation_summary"]
    summary_discarded_mutation_priority = summary_sources["discarded_mutation_priority"]
    summary_pass_evidence_compact = summary_sources["pass_evidence_compact"]
    summary_report_views = summary_sources["report_views"]
    summary_discarded_view = summary_sources["discarded_view"]
    summary_general_passes = summary_sources["general_passes"]
    summary_general_pass_rows = summary_sources["general_pass_rows"]
    summary_general_symbolic = summary_sources["general_symbolic"]
    summary_general_discards = summary_sources["general_discards"]

    for pass_name in filtered_summary["passes"]:
        capabilities = summary_pass_capabilities.get(pass_name)
        if capabilities is None:
            normalized_row = normalized_pass_map.get(pass_name, {})
            if normalized_row:
                capabilities = {
                    "runtime": {"recommended": bool(normalized_row.get("runtime_recommended", False))},
                    "symbolic": {
                        "recommended": bool(normalized_row.get("symbolic_recommended", False)),
                        "confidence": normalized_row.get("symbolic_confidence", "unknown"),
                    },
                }
        if capabilities is None:
            support = pass_support.get(pass_name)
            if support:
                capabilities = support.get("validator_capabilities", {})
        if capabilities:
            filtered_summary["pass_capabilities"][pass_name] = dict(capabilities)

        context = summary_pass_validation_context.get(
            pass_name, pass_results.get(pass_name, {}).get("validation_context")
        )
        if not context:
            normalized_row = normalized_pass_map.get(pass_name, {})
            if normalized_row:
                context = {
                    "role": normalized_row.get("role", "requested-mode"),
                    "requested_validation_mode": requested_validation_mode,
                    "effective_validation_mode": effective_validation_mode,
                    "degraded_execution": normalized_row.get("role") == "executed-under-degraded-mode",
                    "degradation_triggered_by_pass": normalized_row.get("role") == "degradation-trigger",
                }
        if context:
            context_payload = dict(context)
            context_payload["role"] = (
                "degradation-trigger"
                if context.get("degradation_triggered_by_pass")
                else "executed-under-degraded-mode"
                if context.get("degraded_execution")
                else "requested-mode"
            )
            filtered_summary["pass_validation_context"][pass_name] = context_payload

    if not degradation_roles:
        for context in filtered_summary["pass_validation_context"].values():
            role = context.get("role")
            if role:
                degradation_roles[role] = degradation_roles.get(role, 0) + 1

    _populate_filtered_summary_symbolic_sections(
        filtered_summary=filtered_summary,
        summary=summary,
        pass_results=pass_results,
        by_pass=by_pass,
        degraded_passes=degraded_passes,
        only_degraded=only_degraded,
        summary_symbolic_issue_map=summary_symbolic_issue_map,
        summary_symbolic_coverage_map=summary_symbolic_coverage_map,
        summary_symbolic_severity_map=summary_symbolic_severity_map,
        summary_pass_symbolic_summary=summary_pass_symbolic_summary,
    )

    pass_evidence_priority_rows = list(summary.get("pass_evidence_priority", []))
    if pass_evidence_priority_rows:
        filtered_summary["pass_evidence"] = [
            dict(row) for row in pass_evidence_priority_rows if row.get("pass_name") in filtered_summary["passes"]
        ]
    elif summary_pass_evidence_compact:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(row)
                for row in summary_pass_evidence_compact
                if not visible_passes or row.get("pass_name") in visible_passes
            ]
        )
    else:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                row
                for row in list(summary.get("pass_evidence", []))
                if row.get("pass_name") in filtered_summary["passes"]
            ]
        )

    if not filtered_summary["symbolic_issue_passes"] and summary_general_symbolic.get("triage_rows"):
        filtered_summary["symbolic_issue_passes"] = [
            dict(row) for row in list(summary_general_symbolic.get("triage_rows", []))
        ]
    if not filtered_summary["symbolic_issue_passes"]:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["symbolic_issue_passes"] = [
            dict(row)
            for pass_name, row in summary_symbolic_issue_map.items()
            if not visible_passes or pass_name in visible_passes
        ]
    if not filtered_summary["symbolic_issue_passes"]:
        filtered_summary["symbolic_issue_passes"] = [
            issue
            for pass_name in filtered_summary["passes"]
            for issue in pass_results.get(pass_name, {}).get("symbolic_summary", {}).get("issues", [])
        ]
    if not filtered_summary["symbolic_issue_passes"]:
        filtered_summary["symbolic_issue_passes"] = [
            {
                "pass_name": pass_name,
                "severity": (
                    "mismatch"
                    if pass_stats["observable_mismatch"] > 0
                    else "without-coverage"
                    if pass_stats["without_coverage"] > 0
                    else "bounded-only"
                ),
                "observable_mismatch": pass_stats["observable_mismatch"],
                "without_coverage": pass_stats["without_coverage"],
                "bounded_only": pass_stats["bounded_only"],
            }
            for pass_name, pass_stats in sorted(
                (
                    (name, stats)
                    for name, stats in by_pass.items()
                    if stats["observable_mismatch"] > 0 or stats["without_coverage"] > 0 or stats["bounded_only"] > 0
                ),
                key=lambda item: (
                    -item[1]["observable_mismatch"],
                    -item[1]["without_coverage"],
                    -item[1]["bounded_only"],
                    item[0],
                ),
            )
        ]

    if not filtered_summary["symbolic_coverage_by_pass"]:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["symbolic_coverage_by_pass"] = [
            dict(row)
            for pass_name, row in summary_symbolic_coverage_map.items()
            if not visible_passes or pass_name in visible_passes
        ]
    if not filtered_summary["symbolic_coverage_by_pass"]:
        filtered_summary["symbolic_coverage_by_pass"] = [
            pass_results.get(pass_name, {}).get("symbolic_summary", {})
            for pass_name in filtered_summary["passes"]
            if pass_results.get(pass_name, {}).get("symbolic_summary", {}).get("symbolic_requested", 0) > 0
        ]
    if not filtered_summary["symbolic_coverage_by_pass"]:
        filtered_summary["symbolic_coverage_by_pass"] = [
            {"pass_name": pass_name, **pass_stats}
            for pass_name, pass_stats in sorted(
                ((name, stats) for name, stats in by_pass.items() if stats["symbolic_requested"] > 0),
                key=lambda item: (
                    -item[1]["symbolic_requested"],
                    -item[1]["observable_match"],
                    -item[1]["observable_mismatch"],
                    item[0],
                ),
            )
        ]

    if not filtered_summary["symbolic_severity_by_pass"]:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["symbolic_severity_by_pass"] = [
            dict(row)
            for pass_name, row in summary_symbolic_severity_map.items()
            if not visible_passes or pass_name in visible_passes
        ]
    if not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": summary_row.get("severity", "not-requested"),
                "issue_count": summary_row.get("issue_count", 0),
                "symbolic_requested": summary_row.get("symbolic_requested", 0),
            }
            for pass_name, summary_row in sorted(
                filtered_summary["pass_symbolic_summary"].items(),
                key=lambda item: item[0],
            )
        ]
    if only_degraded and degraded_passes and not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": filtered_summary["pass_symbolic_summary"]
                .get(pass_name, {})
                .get("severity", "not-requested"),
                "issue_count": filtered_summary["pass_symbolic_summary"].get(pass_name, {}).get("issue_count", 0),
                "symbolic_requested": filtered_summary["pass_symbolic_summary"]
                .get(pass_name, {})
                .get("symbolic_requested", 0),
            }
            for pass_name in [item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes]
        ]

    filtered_summary["degradation_roles"] = degradation_roles
    for pass_name in filtered_summary["passes"]:
        pass_symbolic_summary = summary_pass_symbolic_summary.get(
            pass_name, pass_results.get(pass_name, {}).get("symbolic_summary")
        )
        if not pass_symbolic_summary:
            normalized_row = normalized_pass_map.get(pass_name, {})
            if normalized_row:
                pass_symbolic_summary = {
                    "pass_name": pass_name,
                    "severity": normalized_row.get("severity", "not-requested"),
                    "issue_count": normalized_row.get("issue_count", 0),
                    "symbolic_requested": normalized_row.get("symbolic_requested", 0),
                    "observable_match": normalized_row.get("observable_match", 0),
                    "observable_mismatch": normalized_row.get("observable_mismatch", 0),
                    "bounded_only": normalized_row.get("bounded_only", 0),
                    "without_coverage": normalized_row.get("without_coverage", 0),
                    "issues": [],
                }
        if pass_symbolic_summary:
            filtered_summary["pass_symbolic_summary"][pass_name] = dict(pass_symbolic_summary)

    if not filtered_summary["pass_validation_context"] and summary_pass_validation_context:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_validation_context"] = {
            pass_name: dict(context)
            for pass_name, context in summary_pass_validation_context.items()
            if not visible_passes or pass_name in visible_passes
        }
    if not filtered_summary["pass_symbolic_summary"] and summary_pass_symbolic_summary:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_symbolic_summary"] = {
            pass_name: dict(summary_row)
            for pass_name, summary_row in summary_pass_symbolic_summary.items()
            if not visible_passes or pass_name in visible_passes
        }
    if not filtered_summary["pass_capabilities"] and summary_pass_capabilities:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capabilities"] = {
            pass_name: dict(capabilities)
            for pass_name, capabilities in summary_pass_capabilities.items()
            if not visible_passes or pass_name in visible_passes
        }

    pass_triage_rows = list(
        _summary_first(summary, "pass_triage_rows", summary_report_views.get("triage_priority", [])) or []
    )
    if pass_triage_rows:
        filtered_summary["pass_triage_rows"] = _visible_rows(
            pass_triage_rows,
            set(filtered_summary["passes"]),
        )
    elif summary_pass_triage_map:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_triage_rows"] = [
            dict(row)
            for pass_name, row in summary_pass_triage_map.items()
            if not visible_passes or pass_name in visible_passes
        ]
    if summary_normalized_pass_results:
        filtered_summary["normalized_pass_results"] = _visible_rows(
            summary_normalized_pass_results,
            set(filtered_summary["passes"]),
        )
    elif summary_general_pass_rows:
        filtered_summary["normalized_pass_results"] = _visible_rows(
            summary_general_pass_rows,
            set(filtered_summary["passes"]),
        )
    elif summary_general_passes:
        filtered_summary["normalized_pass_results"] = _visible_rows(
            summary_general_passes,
            set(filtered_summary["passes"]),
        )

    capability_rows = list(summary.get("pass_capability_summary", []))
    if capability_rows:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capability_summary"] = [
            dict(row) for row in capability_rows if not visible_passes or row.get("pass_name") in visible_passes
        ]
    elif summary_pass_capability_summary_map:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capability_summary"] = [
            dict(row)
            for pass_name, row in summary_pass_capability_summary_map.items()
            if not visible_passes or pass_name in visible_passes
        ]
    elif summary_general_pass_rows:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capability_summary"] = [
            {
                "pass_name": str(row.get("pass_name")),
                "runtime_recommended": bool(row.get("runtime_recommended", False)),
                "symbolic_recommended": bool(row.get("symbolic_recommended", False)),
                "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
            }
            for row in summary_general_pass_rows
            if row.get("pass_name") and (not visible_passes or row.get("pass_name") in visible_passes)
        ]

    validation_role_rows = list(summary.get("validation_role_rows", []))
    if validation_role_rows:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["validation_role_rows"] = [
            dict(row) for row in validation_role_rows if not visible_passes or row.get("pass_name") in visible_passes
        ]
    elif summary_validation_role_map:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["validation_role_rows"] = [
            dict(row)
            for pass_name, row in summary_validation_role_map.items()
            if not visible_passes or pass_name in visible_passes
        ]

    _populate_filtered_summary_discarded_sections(
        filtered_summary=filtered_summary,
        summary_discarded_mutation_summary=summary_discarded_mutation_summary,
        summary_discarded_view=summary_discarded_view,
        summary_discarded_mutation_priority=summary_discarded_mutation_priority,
    )
    if "discarded_mutation_compact_summary" not in filtered_summary and summary_general_discards.get("summary"):
        filtered_summary["discarded_mutation_compact_summary"] = dict(summary_general_discards.get("summary", {}))
    if "discarded_mutation_compact_rows" not in filtered_summary and summary_general_discards.get("rows"):
        filtered_summary["discarded_mutation_compact_rows"] = list(summary_general_discards.get("rows", []))
    visible_passes = set(filtered_summary["passes"])
    if summary_pass_region_evidence_map:
        filtered_summary["pass_region_evidence_map"] = {
            pass_name: list(rows)
            for pass_name, rows in summary_pass_region_evidence_map.items()
            if not visible_passes or pass_name in visible_passes
        }
    if not filtered_summary["pass_evidence"]:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(pass_results.get(pass_name, {}).get("evidence_summary", {}))
                for pass_name in filtered_summary["passes"]
                if pass_results.get(pass_name, {}).get("evidence_summary")
            ]
        )
    if not filtered_summary["pass_evidence"] and summary_pass_evidence_map:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(row)
                for pass_name, row in summary_pass_evidence_map.items()
                if (not visible_passes or pass_name in visible_passes) and row.get("pass_name")
            ]
        )
    if not filtered_summary["pass_evidence"] and summary_general_pass_rows:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                {
                    "pass_name": row.get("pass_name"),
                    "changed_region_count": row.get("changed_region_count", 0),
                    "changed_bytes": row.get("changed_bytes", 0),
                    "structural_issue_count": row.get("structural_issue_count", 0),
                    "symbolic_binary_mismatched_regions": row.get("symbolic_binary_mismatched_regions", 0),
                }
                for row in summary_general_pass_rows
                if row.get("pass_name") and (not visible_passes or row.get("pass_name") in visible_passes)
            ]
        )
    if not filtered_summary["pass_evidence"] and filtered_summary["normalized_pass_results"]:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                {
                    "pass_name": row.get("pass_name"),
                    "changed_region_count": row.get("changed_region_count", 0),
                    "changed_bytes": row.get("changed_bytes", 0),
                    "structural_issue_count": row.get("structural_issue_count", 0),
                    "symbolic_binary_mismatched_regions": row.get("symbolic_binary_mismatched_regions", 0),
                }
                for row in filtered_summary["normalized_pass_results"]
                if row.get("pass_name")
            ]
        )
    if not filtered_summary["pass_evidence"] and normalized_pass_map:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                {
                    "pass_name": pass_name,
                    "changed_region_count": row.get("changed_region_count", 0),
                    "changed_bytes": row.get("changed_bytes", 0),
                    "structural_issue_count": row.get("structural_issue_count", 0),
                    "symbolic_binary_mismatched_regions": row.get("symbolic_binary_mismatched_regions", 0),
                }
                for pass_name, row in normalized_pass_map.items()
                if pass_name in set(filtered_summary["passes"])
            ]
        )
    if only_risky_filters and not filtered_summary["pass_evidence"]:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(pass_results.get(pass_name, {}).get("evidence_summary", {}))
                for pass_name in sorted(selected_risk_pass_names)
                if pass_results.get(pass_name, {}).get("evidence_summary")
                and (resolved_only_pass is None or pass_name == resolved_only_pass)
            ]
        )

    if only_risky_filters:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [row for row in filtered_summary["pass_evidence"] if row.get("pass_name") in selected_risk_pass_names]
        )
        filtered_summary["symbolic_issue_passes"] = [
            row for row in filtered_summary["symbolic_issue_passes"] if row.get("pass_name") in selected_risk_pass_names
        ]
        filtered_summary["symbolic_coverage_by_pass"] = [
            row
            for row in filtered_summary["symbolic_coverage_by_pass"]
            if row.get("pass_name") in selected_risk_pass_names
        ]
        filtered_summary["symbolic_severity_by_pass"] = [
            row
            for row in filtered_summary["symbolic_severity_by_pass"]
            if row.get("pass_name") in selected_risk_pass_names
        ]
        filtered_summary["pass_capabilities"] = {
            pass_name: capabilities
            for pass_name, capabilities in filtered_summary["pass_capabilities"].items()
            if pass_name in selected_risk_pass_names
        }
        filtered_summary["pass_validation_context"] = {
            pass_name: context
            for pass_name, context in filtered_summary["pass_validation_context"].items()
            if pass_name in selected_risk_pass_names
        }
        filtered_summary["pass_symbolic_summary"] = {
            pass_name: summary_row
            for pass_name, summary_row in filtered_summary["pass_symbolic_summary"].items()
            if pass_name in selected_risk_pass_names
        }

    if not filtered_summary["pass_symbolic_summary"]:
        for row in filtered_summary["symbolic_coverage_by_pass"]:
            pass_name = row.get("pass_name")
            if not pass_name:
                continue
            filtered_summary["pass_symbolic_summary"][pass_name] = {
                **row,
                "issues": [
                    issue for issue in filtered_summary["symbolic_issue_passes"] if issue.get("pass_name") == pass_name
                ],
            }
    if not filtered_summary["pass_symbolic_summary"] and filtered_summary["normalized_pass_results"]:
        for row in filtered_summary["normalized_pass_results"]:
            pass_name = row.get("pass_name")
            if not pass_name:
                continue
            filtered_summary["pass_symbolic_summary"][str(pass_name)] = {
                "pass_name": str(pass_name),
                "severity": row.get("severity", "not-requested"),
                "issue_count": row.get("issue_count", 0),
                "symbolic_requested": row.get("symbolic_requested", 0),
                "observable_match": row.get("observable_match", 0),
                "observable_mismatch": row.get("observable_mismatch", 0),
                "bounded_only": row.get("bounded_only", 0),
                "without_coverage": row.get("without_coverage", 0),
                "issues": [],
            }
    if only_risky_filters and not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": summary_row.get("severity", "not-requested"),
                "issue_count": summary_row.get("issue_count", 0),
                "symbolic_requested": summary_row.get("symbolic_requested", 0),
            }
            for pass_name, summary_row in sorted(
                filtered_summary["pass_symbolic_summary"].items(),
                key=lambda item: item[0],
            )
        ]
    return degradation_roles


def _resolve_summary_pass_sources(summary: dict[str, Any]) -> dict[str, Any]:
    """Resolve summary-first pass-related sources in one place."""
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    general_renderer_state = resolved_general_views["general_renderer_state"]
    general_renderer_passes = list(general_renderer_state.get("passes", []) or [])
    general_renderer_general_passes = list(general_renderer_state.get("general_passes", []) or [])
    general_renderer_general_pass_rows = list(general_renderer_state.get("general_pass_rows", []) or [])
    general_renderer_pass_rows = list(
        general_renderer_state.get(
            "pass_rows",
            general_renderer_general_pass_rows or general_renderer_general_passes or general_renderer_passes,
        )
        or general_renderer_general_pass_rows
        or general_renderer_general_passes
        or general_renderer_passes
    )
    general_renderer_triage_rows = list(
        general_renderer_state.get(
            "general_triage_rows",
            general_renderer_state.get("triage_rows", []),
        )
        or []
    )
    return {
        "pass_validation_context": dict(summary.get("pass_validation_context", {}) or {}),
        "pass_symbolic_summary": dict(summary.get("pass_symbolic_summary", {}) or {}),
        "pass_capabilities": dict(summary.get("pass_capabilities", {}) or {}),
        "pass_evidence_map": dict(summary.get("pass_evidence_map", {}) or {}),
        "pass_region_evidence_map": dict(summary.get("pass_region_evidence_map", {}) or {}),
        "pass_triage_map": dict(summary.get("pass_triage_map", {}) or {}),
        "normalized_pass_results": list(summary.get("normalized_pass_results", []) or []),
        "symbolic_issue_map": dict(summary.get("symbolic_issue_map", {}) or {}),
        "symbolic_coverage_map": dict(summary.get("symbolic_coverage_map", {}) or {}),
        "symbolic_severity_map": dict(summary.get("symbolic_severity_map", {}) or {}),
        "pass_capability_summary_map": dict(summary.get("pass_capability_summary_map", {}) or {}),
        "validation_role_map": dict(summary.get("validation_role_map", {}) or {}),
        "discarded_mutation_summary": dict(summary.get("discarded_mutation_summary", {}) or {}),
        "discarded_mutation_priority": list(summary.get("discarded_mutation_priority", []) or []),
        "pass_evidence_compact": list(summary.get("pass_evidence_compact", [])),
        "report_views": report_views,
        "discarded_view": dict(report_views.get("discarded_view", {}) or {}),
        "general_passes": list(
            report_views.get("general_passes", []) or general_renderer_general_passes or general_renderer_passes
        ),
        "general_pass_rows": list(report_views.get("general_pass_rows", []) or general_renderer_pass_rows),
        "general_summary": resolved_general_views["general_summary"],
        "general_symbolic": resolved_general_views["general_symbolic"],
        "general_gates": resolved_general_views["general_gates"],
        "general_degradation": resolved_general_views["general_degradation"],
        "general_discards": resolved_general_views["general_discards"],
        "general_triage_rows": list(report_views.get("general_triage_rows", []) or general_renderer_triage_rows),
    }


def _populate_filtered_summary_symbolic_sections(
    *,
    filtered_summary: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
    degraded_passes: list[dict[str, Any]],
    only_degraded: bool,
    summary_symbolic_issue_map: dict[str, Any],
    summary_symbolic_coverage_map: dict[str, Any],
    summary_symbolic_severity_map: dict[str, Any],
    summary_pass_symbolic_summary: dict[str, Any],
) -> None:
    """Populate symbolic report sections with summary-first fallbacks."""
    filtered_summary["symbolic_issue_passes"] = list(summary.get("symbolic_issue_passes", []))
    filtered_summary["symbolic_coverage_by_pass"] = list(summary.get("symbolic_coverage_by_pass", []))
    filtered_summary["symbolic_severity_by_pass"] = list(summary.get("symbolic_severity_by_pass", []))

    if not filtered_summary["symbolic_issue_passes"]:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["symbolic_issue_passes"] = [
            dict(row)
            for pass_name, row in summary_symbolic_issue_map.items()
            if not visible_passes or pass_name in visible_passes
        ]
    if not filtered_summary["symbolic_issue_passes"]:
        filtered_summary["symbolic_issue_passes"] = [
            issue
            for pass_name in filtered_summary["passes"]
            for issue in pass_results.get(pass_name, {}).get("symbolic_summary", {}).get("issues", [])
        ]
    if not filtered_summary["symbolic_issue_passes"]:
        filtered_summary["symbolic_issue_passes"] = [
            {
                "pass_name": pass_name,
                "severity": (
                    "mismatch"
                    if pass_stats["observable_mismatch"] > 0
                    else "without-coverage"
                    if pass_stats["without_coverage"] > 0
                    else "bounded-only"
                ),
                "observable_mismatch": pass_stats["observable_mismatch"],
                "without_coverage": pass_stats["without_coverage"],
                "bounded_only": pass_stats["bounded_only"],
            }
            for pass_name, pass_stats in sorted(
                (
                    (name, stats)
                    for name, stats in by_pass.items()
                    if stats["observable_mismatch"] > 0 or stats["without_coverage"] > 0 or stats["bounded_only"] > 0
                ),
                key=lambda item: (
                    -item[1]["observable_mismatch"],
                    -item[1]["without_coverage"],
                    -item[1]["bounded_only"],
                    item[0],
                ),
            )
        ]

    if not filtered_summary["symbolic_coverage_by_pass"]:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["symbolic_coverage_by_pass"] = [
            dict(row)
            for pass_name, row in summary_symbolic_coverage_map.items()
            if not visible_passes or pass_name in visible_passes
        ]
    if not filtered_summary["symbolic_coverage_by_pass"]:
        filtered_summary["symbolic_coverage_by_pass"] = [
            pass_results.get(pass_name, {}).get("symbolic_summary", {})
            for pass_name in filtered_summary["passes"]
            if pass_results.get(pass_name, {}).get("symbolic_summary", {}).get("symbolic_requested", 0) > 0
        ]
    if not filtered_summary["symbolic_coverage_by_pass"]:
        filtered_summary["symbolic_coverage_by_pass"] = [
            {"pass_name": pass_name, **pass_stats}
            for pass_name, pass_stats in sorted(
                ((name, stats) for name, stats in by_pass.items() if stats["symbolic_requested"] > 0),
                key=lambda item: (
                    -item[1]["symbolic_requested"],
                    -item[1]["observable_match"],
                    -item[1]["observable_mismatch"],
                    item[0],
                ),
            )
        ]

    if not filtered_summary["symbolic_severity_by_pass"]:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["symbolic_severity_by_pass"] = [
            dict(row)
            for pass_name, row in summary_symbolic_severity_map.items()
            if not visible_passes or pass_name in visible_passes
        ]
    if not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": summary_row.get("severity", "not-requested"),
                "issue_count": summary_row.get("issue_count", 0),
                "symbolic_requested": summary_row.get("symbolic_requested", 0),
            }
            for pass_name, summary_row in sorted(
                summary_pass_symbolic_summary.items(),
                key=lambda item: item[0],
            )
        ]
    if only_degraded and degraded_passes and not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": filtered_summary["pass_symbolic_summary"]
                .get(pass_name, {})
                .get("severity", "not-requested"),
                "issue_count": filtered_summary["pass_symbolic_summary"].get(pass_name, {}).get("issue_count", 0),
                "symbolic_requested": filtered_summary["pass_symbolic_summary"]
                .get(pass_name, {})
                .get("symbolic_requested", 0),
            }
            for pass_name in [item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes]
        ]


def _populate_filtered_summary_discarded_sections(
    *,
    filtered_summary: dict[str, Any],
    summary_discarded_mutation_summary: dict[str, Any],
    summary_discarded_view: dict[str, Any],
    summary_discarded_mutation_priority: list[dict[str, Any]],
) -> None:
    """Populate discarded-mutation sections with summary-first compact/final rows."""
    if summary_discarded_mutation_summary:
        filtered_summary["discarded_mutation_summary"] = summary_discarded_mutation_summary
    if summary_discarded_view:
        if summary_discarded_view.get("final_by_pass"):
            filtered_summary["discarded_mutation_final_by_pass"] = dict(summary_discarded_view.get("final_by_pass", {}))
        if summary_discarded_view.get("final_rows"):
            filtered_summary["discarded_mutation_final_rows"] = list(summary_discarded_view.get("final_rows", []))
        if summary_discarded_view.get("compact_rows"):
            filtered_summary["discarded_mutation_compact_rows"] = list(summary_discarded_view.get("compact_rows", []))
        if summary_discarded_view.get("compact_by_pass"):
            filtered_summary["discarded_mutation_compact_by_pass"] = dict(
                summary_discarded_view.get("compact_by_pass", {})
            )
        if summary_discarded_view.get("compact_by_reason"):
            filtered_summary["discarded_mutation_compact_by_reason"] = dict(
                summary_discarded_view.get("compact_by_reason", {})
            )
        if summary_discarded_view.get("compact_summary"):
            filtered_summary["discarded_mutation_compact_summary"] = dict(
                summary_discarded_view.get("compact_summary", {})
            )
    elif summary_discarded_mutation_priority:
        if "discarded_mutation_final_rows" not in filtered_summary:
            filtered_summary["discarded_mutation_final_rows"] = [
                {
                    "pass_name": row.get("pass_name"),
                    "reasons": list(row.get("reasons", {}).keys()) if isinstance(row.get("reasons"), dict) else [],
                }
                for row in summary_discarded_mutation_priority
                if row.get("pass_name")
            ]
        if "discarded_mutation_compact_rows" not in filtered_summary:
            filtered_summary["discarded_mutation_compact_rows"] = list(summary_discarded_mutation_priority)
        if "discarded_mutation_compact_by_reason" not in filtered_summary:
            by_reason: dict[str, int] = {}
            for row in summary_discarded_mutation_priority:
                reasons = row.get("reasons", {})
                if isinstance(reasons, dict):
                    for reason, count in reasons.items():
                        by_reason[reason] = by_reason.get(reason, 0) + count
            filtered_summary["discarded_mutation_compact_by_reason"] = by_reason


def _normalized_pass_map(
    normalized_pass_results: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index normalized per-pass rows by pass name."""
    return {str(row.get("pass_name")): dict(row) for row in normalized_pass_results if row.get("pass_name")}


def _resolve_only_pass_view(
    *,
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    pass_results: dict[str, Any],
    pass_name: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Resolve pass-scoped symbolic/evidence/context views with summary-first fallbacks."""
    report_views = dict(summary.get("report_views", {}) or {})
    only_pass_map = dict(report_views.get("only_pass", {}) or {})
    summary_pass_symbolic_summary = dict(summary.get("pass_symbolic_summary", {}) or {})
    summary_pass_validation_context = dict(summary.get("pass_validation_context", {}) or {})
    summary_pass_region_evidence_map = dict(summary.get("pass_region_evidence_map", {}) or {})
    normalized_pass_map = _normalized_pass_map(list(summary.get("normalized_pass_results", []) or []))
    symbolic_summary = filtered_summary.get("pass_symbolic_summary", {}).get(pass_name)
    if symbolic_summary is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        symbolic_summary = compact_row.get("symbolic_summary") or summary_pass_symbolic_summary.get(pass_name)
    if symbolic_summary is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        normalized_row = normalized_pass_map.get(pass_name) or compact_row.get("normalized") or compact_row
        if normalized_row:
            symbolic_summary = {
                "pass_name": pass_name,
                "severity": normalized_row.get("severity", "not-requested"),
                "issue_count": normalized_row.get("issue_count", 0),
                "symbolic_requested": normalized_row.get("symbolic_requested", 0),
                "observable_match": normalized_row.get("observable_match", 0),
                "observable_mismatch": normalized_row.get("observable_mismatch", 0),
                "bounded_only": normalized_row.get("bounded_only", 0),
                "without_coverage": normalized_row.get("without_coverage", 0),
                "issues": [],
            }
    pass_evidence = next(
        (row for row in filtered_summary.get("pass_evidence", []) if row.get("pass_name") == pass_name),
        None,
    )
    if pass_evidence is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        pass_evidence = compact_row.get("evidence")
        normalized_row = normalized_pass_map.get(pass_name) or compact_row.get("normalized") or compact_row
        if normalized_row:
            pass_evidence = pass_evidence or {
                "pass_name": pass_name,
                "changed_region_count": normalized_row.get("changed_region_count", 0),
                "changed_bytes": normalized_row.get("changed_bytes", 0),
                "structural_issue_count": normalized_row.get("structural_issue_count", 0),
                "symbolic_binary_mismatched_regions": normalized_row.get("symbolic_binary_mismatched_regions", 0),
            }
    context = filtered_summary.get("pass_validation_context", {}).get(pass_name)
    if context is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        context = compact_row.get("validation_context") or summary_pass_validation_context.get(
            pass_name, pass_results.get(pass_name, {}).get("validation_context")
        )
    if context is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        normalized_row = normalized_pass_map.get(pass_name) or compact_row.get("normalized") or compact_row
        if normalized_row:
            role = normalized_row.get("role", "requested-mode")
            context = {
                "role": role,
                "requested_validation_mode": filtered_summary.get("requested_validation_mode", "off"),
                "effective_validation_mode": filtered_summary.get("validation_mode", "off"),
                "degraded_execution": role == "executed-under-degraded-mode",
                "degradation_triggered_by_pass": role == "degradation-trigger",
            }
    region_evidence = summary_pass_region_evidence_map.get(pass_name)
    if region_evidence is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        region_evidence = compact_row.get("region_evidence")
    return symbolic_summary, pass_evidence, context, region_evidence


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
    console.print(f"  [cyan]{pass_name}[/cyan]: " + ", ".join(fragments))


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
        console.print("[bold]Pass Symbolic Summary[/bold]:")
        console.print(
            "  "
            f"[cyan]{pass_name}[/cyan]: "
            f"{pass_symbolic_summary.get('observable_match', 0)} match, "
            f"{pass_symbolic_summary.get('observable_mismatch', 0)} mismatch, "
            f"{pass_symbolic_summary.get('bounded_only', 0)} bounded-only, "
            f"{pass_symbolic_summary.get('without_coverage', 0)} without coverage"
        )
        console.print(
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
                console.print(
                    "  "
                    f"issues: {sev}(mismatch={counts['mismatch']}, "
                    f"without_coverage={counts['without_coverage']}, "
                    f"bounded_only={counts['bounded_only']})"
                )
    if pass_evidence:
        console.print("[bold]Pass Evidence Summary[/bold]:")
        console.print(
            "  "
            f"[cyan]{pass_name}[/cyan]: "
            f"changed_regions={pass_evidence.get('changed_region_count', 0)}, "
            f"changed_bytes={pass_evidence.get('changed_bytes', 0)}, "
            f"structural_issues={pass_evidence.get('structural_issue_count', 0)}, "
            f"symbolic_checked={pass_evidence.get('symbolic_binary_regions_checked', 0)}, "
            f"symbolic_mismatch={pass_evidence.get('symbolic_binary_mismatched_regions', 0)}"
        )
    if pass_region_evidence:
        console.print("[bold]Pass Region Evidence[/bold]:")
        for row in pass_region_evidence[:5]:
            start = row.get("start_address")
            end = row.get("end_address")
            if start is None or end is None:
                region = "unknown"
            elif start == end:
                region = f"0x{start:x}"
            else:
                region = f"0x{start:x}-0x{end:x}"
            console.print(
                "  "
                f"[cyan]{region}[/cyan]: "
                f"equivalent={str(bool(row.get('equivalent', False))).lower()}, "
                f"mismatch_count={row.get('mismatch_count', 0)}, "
                f"step={row.get('step_strategy', 'unknown')}, "
                f"trace={row.get('original_trace_length', 0)}/{row.get('mutated_trace_length', 0)}"
            )
    if pass_validation_context:
        console.print("[bold]Pass Validation Context[/bold]:")
        _render_pass_validation_context(pass_name, pass_validation_context)
    if pass_capabilities:
        console.print("[bold]Pass Capabilities[/bold]:")
        fragments = []
        if pass_capabilities.get("runtime_recommended") is not None:
            fragments.append(f"runtime recommended={'yes' if pass_capabilities.get('runtime_recommended') else 'no'}")
        if pass_capabilities.get("symbolic_confidence"):
            fragments.append(f"symbolic confidence={pass_capabilities.get('symbolic_confidence')}")
        if pass_capabilities.get("symbolic_recommended") is not None:
            fragments.append(f"symbolic recommended={'yes' if pass_capabilities.get('symbolic_recommended') else 'no'}")
        if fragments:
            console.print(f"  [cyan]{pass_name}[/cyan]: " + ", ".join(fragments))


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
        console.print(
            "[bold]Validation Mode Adjustment[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )
        if validation_policy is not None:
            console.print(
                f"  policy={validation_policy.get('policy', 'unknown')}, "
                f"reason={validation_policy.get('reason', 'unknown')}"
            )
            if degraded_passes:
                console.print("[bold]Degraded Passes[/bold]:")
                for item in degraded_passes:
                    pass_name = item.get("pass_name", item.get("mutation", "unknown"))
                    confidence = item.get("confidence", "unknown")
                    console.print(f"  [yellow]{pass_name}[/yellow]: symbolic confidence={confidence}")
            if degradation_roles:
                console.print("[bold]Degradation Roles[/bold]:")
                for role, count in sorted(degradation_roles.items()):
                    console.print(f"  {role}: {count}")
            if symbolic_severity_rows:
                console.print("[bold]Degraded Severity Priority[/bold]:")
                for row in symbolic_severity_rows:
                    console.print(
                        f"  [cyan]{row['pass_name']}[/cyan]: "
                        f"severity={row.get('severity', 'unknown')}, "
                        f"issue_count={row.get('issue_count', 0)}, "
                        f"symbolic_requested={row.get('symbolic_requested', 0)}"
                    )
    elif requested_validation_mode:
        console.print(
            "[bold]Validation Mode[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )


def _render_general_report_sections(
    *,
    filtered_summary: dict[str, Any],
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
) -> None:
    """Render the general non-mismatch report sections."""
    degraded_severity_rows = [
        row
        for row in filtered_summary["symbolic_severity_by_pass"]
        if row.get("pass_name") in {item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes}
    ]
    _render_degradation_sections(
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        validation_policy=validation_policy,
        degraded_passes=degraded_passes,
        degradation_roles=degradation_roles,
        symbolic_severity_rows=degraded_severity_rows,
    )
    if gate_evaluation:
        _render_gate_sections(
            gate_evaluation=gate_evaluation,
            gate_requested=gate_requested,
            gate_results=gate_results,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=filtered_summary.get("gate_failure_priority", []) or gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
        )
    _render_pass_capabilities(filtered_summary=filtered_summary)
    if pass_results:
        _render_pass_validation_contexts(
            filtered_summary=filtered_summary,
            pass_results=pass_results,
            degraded_passes=degraded_passes,
        )


def _render_general_only_pass_sections(
    *,
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    pass_results: dict[str, Any],
    resolved_only_pass: str | None,
) -> None:
    """Render single-pass sections for the general report flow."""
    if not resolved_only_pass:
        return
    (
        pass_symbolic_summary,
        pass_evidence,
        pass_validation_context,
        pass_region_evidence,
    ) = _resolve_only_pass_view(
        summary=summary,
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        pass_name=resolved_only_pass,
    )
    capability_map = dict(summary.get("pass_capability_summary_map", {}) or {})
    capability_row = filtered_summary.get("pass_capability_summary", {})
    if isinstance(capability_row, list):
        capability_row = next(
            (row for row in capability_row if row.get("pass_name") == resolved_only_pass),
            None,
        )
    elif isinstance(capability_row, dict):
        capability_row = capability_row.get(resolved_only_pass)
    if capability_row is None:
        capability_row = capability_map.get(resolved_only_pass)
    if capability_row is None:
        capability_row = (
            dict(summary.get("report_views", {}) or {})
            .get("only_pass", {})
            .get(resolved_only_pass, {})
            .get("capabilities")
        )
    _render_only_pass_sections(
        pass_name=resolved_only_pass,
        pass_symbolic_summary=pass_symbolic_summary,
        pass_evidence=pass_evidence,
        pass_validation_context=pass_validation_context,
        pass_region_evidence=pass_region_evidence,
        pass_capabilities=capability_row,
    )


def _render_general_flow_sections(
    *,
    filtered_summary: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    symbolic_state: dict[str, Any],
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
) -> None:
    """Render the general report sections before output emission."""
    _render_general_report_sections(
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        degraded_passes=degraded_passes,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        validation_policy=validation_policy,
        gate_evaluation=gate_evaluation,
        gate_requested=gate_requested,
        gate_results=gate_results,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        degradation_roles=degradation_roles,
    )
    _render_general_only_pass_sections(
        summary=summary,
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        resolved_only_pass=resolved_only_pass,
    )
    _render_symbolic_sections(
        symbolic_requested=symbolic_state.get("symbolic_requested", 0),
        observable_match=symbolic_state.get("observable_match", 0),
        observable_mismatch=symbolic_state.get("observable_mismatch", 0),
        bounded_only=symbolic_state.get("bounded_only", 0),
        observable_not_run=symbolic_state.get("observable_not_run", 0),
        summary=filtered_summary,
        pass_results=pass_results,
        by_pass=symbolic_state.get("by_pass", {}),
        mismatch_rows=symbolic_state.get("mismatch_rows", []),
    )


def _execute_general_report_flow(
    *,
    payload: dict[str, Any],
    filtered_summary: dict[str, Any],
    mutations: list[dict[str, Any]],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    symbolic_state: dict[str, Any],
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
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    min_severity: str | None,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
    output: Path | None,
    summary_only: bool,
    require_results: bool,
    min_severity_rank: int | None,
    failed_gates: bool,
) -> None:
    """Render and emit the general report path."""
    _render_general_flow_sections(
        filtered_summary=filtered_summary,
        summary=summary,
        pass_results=pass_results,
        symbolic_state=symbolic_state,
        degraded_passes=degraded_passes,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        validation_policy=validation_policy,
        gate_evaluation=gate_evaluation,
        gate_requested=gate_requested,
        gate_results=gate_results,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        degradation_roles=degradation_roles,
        resolved_only_pass=resolved_only_pass,
    )
    filtered_payload = _build_general_report_payload(
        payload=payload,
        mutations=mutations,
        filtered_summary=filtered_summary,
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        min_severity=min_severity,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
    )
    _finalize_report_output(
        filtered_payload=filtered_payload,
        output=output,
        summary_only=summary_only,
        require_results=require_results,
        min_severity_rank=min_severity_rank,
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
    )


def _dispatch_report_flow_ctx(ctx: "ReportFlowContext") -> None:
    """Dispatch between general and mismatch-specific report flows.

    Uses ReportFlowContext dataclass to pass structured state instead
    of 43 individual parameters. Sub-dataclasses provide grouped access.
    """
    _render_report_filter_messages(
        only_pass=ctx.filters.only_pass,
        resolved_only_pass=ctx.severity.resolved_only_pass,
        only_pass_failure=ctx.filters.only_pass_failure,
        resolved_only_pass_failure=ctx.severity.resolved_only_pass_failure,
        only_risky_passes=ctx.filters.only_risky_passes,
        only_uncovered_passes=ctx.filters.only_uncovered_passes,
        only_covered_passes=ctx.filters.only_covered_passes,
        only_clean_passes=ctx.filters.only_clean_passes,
        only_structural_risk=ctx.filters.only_structural_risk,
        only_symbolic_risk=ctx.filters.only_symbolic_risk,
        selected_risk_pass_names=ctx.severity.selected_risk_pass_names,
    )
    if ctx.filters.only_mismatches:
        mismatch_state = _resolve_only_mismatches_state(
            summary=ctx.data.summary,
            mutations=ctx.data.mutations,
            filtered_summary=ctx.data.filtered_summary,
            resolved_only_pass=ctx.severity.resolved_only_pass,
            degraded_passes=ctx.validation.degraded_passes,
        )
        _execute_only_mismatches_report_flow(
            payload=ctx.data.payload,
            summary=ctx.data.summary,
            filtered_summary=ctx.data.filtered_summary,
            mismatch_state=mismatch_state,
            pass_support=ctx.data.pass_support,
            requested_validation_mode=ctx.validation.requested_validation_mode,
            effective_validation_mode=ctx.validation.effective_validation_mode,
            degraded_validation=ctx.validation.degraded_validation,
            degraded_passes=ctx.validation.degraded_passes,
            degradation_roles=ctx.validation.degradation_roles,
            failed_gates=ctx.gates.failed_gates,
            gate_evaluation=ctx.gates.gate_evaluation,
            gate_failure_summary=ctx.gates.gate_failure_summary,
            gate_failure_priority=ctx.gates.gate_failure_priority,
            gate_failure_severity_priority=ctx.gates.gate_failure_severity_priority,
            min_severity=ctx.severity.min_severity,
            only_expected_severity=ctx.filters.only_expected_severity,
            resolved_only_pass_failure=ctx.severity.resolved_only_pass_failure,
            validation_policy=ctx.validation.validation_policy,
            resolved_only_pass=ctx.severity.resolved_only_pass,
            only_status=ctx.filters.only_status,
            only_degraded=ctx.filters.only_degraded,
            only_failed_gates=ctx.filters.only_failed_gates,
            only_risky_passes=ctx.filters.only_risky_passes,
            only_uncovered_passes=ctx.filters.only_uncovered_passes,
            only_covered_passes=ctx.filters.only_covered_passes,
            only_clean_passes=ctx.filters.only_clean_passes,
            only_structural_risk=ctx.filters.only_structural_risk,
            only_symbolic_risk=ctx.filters.only_symbolic_risk,
            output=ctx.output.output,
            summary_only=ctx.output.summary_only,
            require_results=ctx.output.require_results,
            min_severity_rank=ctx.severity.min_severity_rank,
        )
        return

    _execute_general_report_flow(
        payload=ctx.data.payload,
        filtered_summary=ctx.data.filtered_summary,
        mutations=ctx.data.mutations,
        summary=ctx.data.summary,
        pass_results=ctx.data.pass_results,
        symbolic_state=ctx.data.symbolic_state,
        degraded_passes=ctx.validation.degraded_passes,
        requested_validation_mode=ctx.validation.requested_validation_mode,
        effective_validation_mode=ctx.validation.effective_validation_mode,
        degraded_validation=ctx.validation.degraded_validation,
        validation_policy=ctx.validation.validation_policy,
        gate_evaluation=ctx.gates.gate_evaluation,
        gate_requested=ctx.gates.gate_requested,
        gate_results=ctx.gates.gate_results,
        gate_failure_summary=ctx.gates.gate_failure_summary,
        gate_failure_priority=ctx.gates.gate_failure_priority,
        gate_failure_severity_priority=ctx.gates.gate_failure_severity_priority,
        degradation_roles=ctx.validation.degradation_roles,
        resolved_only_pass=ctx.severity.resolved_only_pass,
        only_status=ctx.filters.only_status,
        only_degraded=ctx.filters.only_degraded,
        only_failed_gates=ctx.filters.only_failed_gates,
        only_risky_passes=ctx.filters.only_risky_passes,
        only_uncovered_passes=ctx.filters.only_uncovered_passes,
        only_covered_passes=ctx.filters.only_covered_passes,
        only_clean_passes=ctx.filters.only_clean_passes,
        only_structural_risk=ctx.filters.only_structural_risk,
        only_symbolic_risk=ctx.filters.only_symbolic_risk,
        min_severity=ctx.severity.min_severity,
        only_expected_severity=ctx.filters.only_expected_severity,
        resolved_only_pass_failure=ctx.severity.resolved_only_pass_failure,
        output=ctx.output.output,
        summary_only=ctx.output.summary_only,
        require_results=ctx.output.require_results,
        min_severity_rank=ctx.severity.min_severity_rank,
        failed_gates=ctx.gates.failed_gates,
    )


def _dispatch_report_flow(**kwargs: Any) -> None:
    """Backward-compatible wrapper that constructs ReportFlowContext from kwargs."""
    from r2morph.reporting.report_context import (
        FilterFlags,
        GateState,
        OutputConfig,
        ReportFlowContext,
        ReportPayload,
        SeverityFilter,
        ValidationState,
    )

    ctx = ReportFlowContext(
        data=ReportPayload(
            payload=kwargs.get("payload", {}),
            summary=kwargs.get("summary", {}),
            filtered_summary=kwargs.get("filtered_summary", {}),
            mutations=kwargs.get("mutations", []),
            pass_results=kwargs.get("pass_results", {}),
            pass_support=kwargs.get("pass_support", {}),
            symbolic_state=kwargs.get("symbolic_state", {}),
        ),
        validation=ValidationState(
            requested_validation_mode=kwargs.get("requested_validation_mode"),
            effective_validation_mode=kwargs.get("effective_validation_mode"),
            degraded_validation=kwargs.get("degraded_validation", False),
            degraded_passes=kwargs.get("degraded_passes", []),
            degradation_roles=kwargs.get("degradation_roles", {}),
            validation_policy=kwargs.get("validation_policy"),
        ),
        gates=GateState(
            failed_gates=kwargs.get("failed_gates", False),
            gate_evaluation=kwargs.get("gate_evaluation", {}),
            gate_requested=kwargs.get("gate_requested", {}),
            gate_results=kwargs.get("gate_results", {}),
            gate_failure_summary=kwargs.get("gate_failure_summary", {}),
            gate_failure_priority=kwargs.get("gate_failure_priority", []),
            gate_failure_severity_priority=kwargs.get("gate_failure_severity_priority", []),
        ),
        filters=FilterFlags(
            only_mismatches=kwargs.get("only_mismatches", False),
            only_status=kwargs.get("only_status"),
            only_degraded=kwargs.get("only_degraded", False),
            only_failed_gates=kwargs.get("only_failed_gates", False),
            only_risky_passes=kwargs.get("only_risky_passes", False),
            only_structural_risk=kwargs.get("only_structural_risk", False),
            only_symbolic_risk=kwargs.get("only_symbolic_risk", False),
            only_uncovered_passes=kwargs.get("only_uncovered_passes", False),
            only_covered_passes=kwargs.get("only_covered_passes", False),
            only_clean_passes=kwargs.get("only_clean_passes", False),
            only_pass=kwargs.get("only_pass"),
            only_pass_failure=kwargs.get("only_pass_failure"),
            only_expected_severity=kwargs.get("only_expected_severity"),
        ),
        severity=SeverityFilter(
            min_severity=kwargs.get("min_severity"),
            min_severity_rank=kwargs.get("min_severity_rank"),
            resolved_only_pass=kwargs.get("resolved_only_pass"),
            resolved_only_pass_failure=kwargs.get("resolved_only_pass_failure"),
            selected_risk_pass_names=kwargs.get("selected_risk_pass_names", set()),
        ),
        output=OutputConfig(
            output=kwargs.get("output"),
            summary_only=kwargs.get("summary_only", False),
            require_results=kwargs.get("require_results", False),
        ),
    )
    _dispatch_report_flow_ctx(ctx)


def _build_report_dispatch_state(
    *,
    context: dict[str, Any],
    general_state: dict[str, Any],
    payload: dict[str, Any],
    pass_results: dict[str, Any],
    only_pass: str | None,
    only_pass_failure: str | None,
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    output: Path | None,
    summary_only: bool,
    require_results: bool,
    min_severity: str | None,
    min_severity_rank: int | None,
    only_expected_severity: str | None,
    only_mismatches: bool,
) -> dict[str, Any]:
    """Assemble the final dispatch state for report()."""
    return {
        "only_mismatches": only_mismatches,
        "payload": payload,
        "summary": context["summary"],
        "filtered_summary": general_state["filtered_summary"],
        "mutations": general_state["mutations"],
        "pass_results": pass_results,
        "pass_support": general_state["pass_support"],
        "requested_validation_mode": context["requested_validation_mode"],
        "effective_validation_mode": context["effective_validation_mode"],
        "degraded_validation": context["degraded_validation"],
        "degraded_passes": general_state["degraded_passes"],
        "degradation_roles": general_state["degradation_roles"],
        "failed_gates": context["failed_gates"],
        "gate_evaluation": context["gate_evaluation"],
        "gate_requested": context["gate_requested"],
        "gate_results": context["gate_results"],
        "gate_failure_summary": context["gate_failure_summary"],
        "gate_failure_priority": context["gate_failure_priority"],
        "gate_failure_severity_priority": context["gate_failure_severity_priority"],
        "validation_policy": context["validation_policy"],
        "resolved_only_pass": context["resolved_only_pass"],
        "resolved_only_pass_failure": context["resolved_only_pass_failure"],
        "only_status": only_status,
        "only_degraded": only_degraded,
        "only_failed_gates": only_failed_gates,
        "only_risky_passes": only_risky_passes,
        "only_structural_risk": only_structural_risk,
        "only_symbolic_risk": only_symbolic_risk,
        "only_uncovered_passes": only_uncovered_passes,
        "only_covered_passes": only_covered_passes,
        "only_clean_passes": only_clean_passes,
        "output": output,
        "summary_only": summary_only,
        "require_results": require_results,
        "min_severity": min_severity,
        "min_severity_rank": min_severity_rank,
        "only_expected_severity": only_expected_severity,
        "only_pass": only_pass,
        "only_pass_failure": only_pass_failure,
        "selected_risk_pass_names": general_state["selected_risk_pass_names"],
        "symbolic_state": general_state["symbolic_state"],
    }


def _build_report_filters(
    *,
    resolved_only_pass: str | None,
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_mismatches: bool = False,
    min_severity: str | None = None,
    only_expected_severity: str | None = None,
    resolved_only_pass_failure: str | None = None,
) -> dict[str, object]:
    """Build a stable report_filters payload."""
    report_filters: dict[str, object] = {}
    if only_mismatches:
        report_filters["only_mismatches"] = True
    if resolved_only_pass:
        report_filters["only_pass"] = resolved_only_pass
    if only_status:
        report_filters["only_status"] = only_status
    if only_degraded:
        report_filters["only_degraded"] = True
    if only_failed_gates:
        report_filters["only_failed_gates"] = True
    if only_risky_passes:
        report_filters["only_risky_passes"] = True
    if only_uncovered_passes:
        report_filters["only_uncovered_passes"] = True
    if only_covered_passes:
        report_filters["only_covered_passes"] = True
    if only_clean_passes:
        report_filters["only_clean_passes"] = True
    if only_structural_risk:
        report_filters["only_structural_risk"] = True
    if only_symbolic_risk:
        report_filters["only_symbolic_risk"] = True
    if min_severity is not None:
        report_filters["min_severity"] = min_severity
    if only_expected_severity is not None:
        report_filters["only_expected_severity"] = only_expected_severity
    if resolved_only_pass_failure is not None:
        report_filters["only_pass_failure"] = resolved_only_pass_failure
    return report_filters


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
    console.print(f"[bold]Gate Evaluation[/bold]: all_passed={'yes' if gate_results.get('all_passed', True) else 'no'}")
    if gate_requested.get("min_severity") is not None:
        console.print(
            "  "
            f"min_severity={gate_requested.get('min_severity')}, "
            f"passed={'yes' if gate_results.get('min_severity_passed', True) else 'no'}"
        )
    if gate_requested.get("require_pass_severity"):
        requested_rules = ", ".join(
            f"{item.get('pass_name')}<={item.get('max_severity')}"
            for item in gate_requested.get("require_pass_severity", [])
        )
        console.print(
            "  "
            f"require_pass_severity={requested_rules}, "
            f"passed={'yes' if gate_results.get('require_pass_severity_passed', True) else 'no'}"
        )
        failures = list(gate_results.get("require_pass_severity_failures", []))
        if failures:
            console.print("  failures: " + ", ".join(failures))
    console.print(
        "[bold]Gate Failure Summary[/bold]: "
        f"min_severity_failed={'yes' if gate_failure_summary.get('min_severity_failed') else 'no'}, "
        f"require_pass_failures={gate_failure_summary.get('require_pass_severity_failure_count', 0)}"
    )
    severity_counts = gate_failure_summary.get("require_pass_severity_failures_by_expected_severity", {})
    if severity_counts:
        console.print(
            "  expected_severity_counts="
            + ", ".join(f"{severity}:{count}" for severity, count in severity_counts.items())
        )
    if gate_failure_severity_priority:
        console.print(
            "  expected_severity_priority="
            + ", ".join(f"{row.get('severity')}:{row.get('failure_count')}" for row in gate_failure_severity_priority)
        )
    pass_failure_map = gate_failure_summary.get("require_pass_severity_failures_by_pass", {})
    if pass_failure_map:
        console.print("[bold]Gate Failure By Pass[/bold]:")
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
            console.print(
                f"  [yellow]{pass_name}[/yellow] "
                f"(count={failure_count}, strictest_expected={strictest}): " + ", ".join(failures)
            )


def _is_risky_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass has issues worth prioritizing in triage views."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if int(evidence_summary.get("symbolic_binary_mismatched_regions", 0)) > 0:
        return True
    if int(evidence_summary.get("structural_issue_count", 0)) > 0:
        return True
    if str(symbolic_summary.get("severity", "not-requested")) in {
        "mismatch",
        "without-coverage",
        "bounded-only",
    }:
        return True
    return int(symbolic_summary.get("issue_count", 0)) > 0


def _has_structural_risk(evidence_summary: dict[str, Any] | None) -> bool:
    """Return True when a pass has structural evidence worth triaging."""
    evidence_summary = evidence_summary or {}
    return int(evidence_summary.get("structural_issue_count", 0)) > 0


def _has_symbolic_risk(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass has symbolic evidence worth triaging."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if int(evidence_summary.get("symbolic_binary_mismatched_regions", 0)) > 0:
        return True
    if str(symbolic_summary.get("severity", "not-requested")) in {
        "mismatch",
        "without-coverage",
        "bounded-only",
    }:
        return True
    return int(symbolic_summary.get("issue_count", 0)) > 0


def _is_clean_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass is clean enough for positive triage views."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if int(evidence_summary.get("structural_issue_count", 0)) > 0:
        return False
    if int(evidence_summary.get("symbolic_binary_mismatched_regions", 0)) > 0:
        return False
    severity = str(symbolic_summary.get("severity", "not-requested"))
    if severity not in {"clean", "not-requested"}:
        return False
    return int(symbolic_summary.get("issue_count", 0)) == 0


def _is_covered_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass is clean and has effective symbolic coverage."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if not _is_clean_pass(evidence_summary, symbolic_summary):
        return False
    if int(symbolic_summary.get("symbolic_requested", 0)) <= 0:
        return False
    if int(symbolic_summary.get("without_coverage", 0)) > 0:
        return False
    return int(evidence_summary.get("symbolic_binary_regions_checked", 0)) > 0


def _is_uncovered_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass is clean but lacks effective symbolic coverage."""
    return _is_clean_pass(evidence_summary, symbolic_summary) and not _is_covered_pass(
        evidence_summary, symbolic_summary
    )


def _expected_severity_rank_from_failure(failure: str) -> int:
    """Extract expected severity rank from a persisted pass failure string."""
    marker = "expected <= "
    if marker not in failure:
        return 99
    severity = failure.split(marker, 1)[1].rstrip(") ").strip()
    return SEVERITY_ORDER.get(severity, 99)


def _add_mutations(
    engine: MorphEngine,
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> None:
    for _mutation_name, mutation_pass in _selected_mutation_passes(
        mutations,
        config,
        seed=seed,
    ):
        engine.add_mutation(mutation_pass)


def _selected_mutation_passes(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> list[tuple[str, object]]:
    """Build pass instances for the selected mutation names."""
    pass_types = _load_mutation_pass_types()
    selected: list[tuple[str, object]] = []
    offset = 0
    if "nop" in mutations:
        selected.append(("nop", pass_types["nop"](config=_mutation_config(config.nop, seed, offset))))
        offset += 1
    if "substitute" in mutations:
        selected.append(
            (
                "substitute",
                pass_types["substitute"](config=_mutation_config(config.substitution, seed, offset)),
            )
        )
        offset += 1
    if "register" in mutations:
        selected.append(
            (
                "register",
                pass_types["register"](config=_mutation_config(config.register, seed, offset)),
            )
        )
        offset += 1
    if "expand" in mutations:
        selected.append(
            (
                "expand",
                pass_types["expand"](config=_mutation_config(config.expansion, seed, offset)),
            )
        )
        offset += 1
    if "block" in mutations:
        selected.append(("block", pass_types["block"](config=_mutation_config(config.block, seed, offset))))
    return selected


def _mutation_pass_alias_map(
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> dict[str, str]:
    """Build aliases from short mutation names to concrete pass names."""
    aliases: dict[str, str] = {}
    all_mutations = list(SUPPORTED_MUTATIONS | EXPERIMENTAL_MUTATIONS)
    for mutation_name, mutation_pass in _selected_mutation_passes(
        all_mutations,
        config,
        seed=seed,
    ):
        aliases[mutation_name] = mutation_pass.name
        aliases[mutation_pass.name] = mutation_pass.name
    return aliases


def _resolve_report_pass_filter(pass_name: str | None) -> str | None:
    """Resolve report-side pass filters using the product alias map."""
    if pass_name is None:
        return None
    alias_map = _mutation_pass_alias_map(_build_config(False, False), seed=None)
    return alias_map.get(pass_name.strip(), pass_name.strip())


def _warn_or_block_limited_symbolic(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None,
    allow_limited_symbolic: bool,
) -> None:
    """Block symbolic mode for passes that declare limited symbolic support unless explicitly allowed."""
    limited = []
    for mutation_name, mutation_pass in _selected_mutation_passes(mutations, config, seed=seed):
        symbolic_support = mutation_pass.get_support().validator_capabilities.get("symbolic", {})
        if symbolic_support.get("recommended") is False:
            limited.append(
                {
                    "mutation": mutation_name,
                    "pass_name": mutation_pass.name,
                    "confidence": symbolic_support.get("confidence", "unknown"),
                }
            )
    if not limited:
        return

    names = ", ".join(item["pass_name"] for item in limited)
    if not allow_limited_symbolic:
        console.print(f"[bold red]Error:[/bold red] symbolic validation is marked limited for: {names}")
        console.print("[yellow]Use structural/runtime, or pass --allow-limited-symbolic to continue anyway.[/yellow]")
        raise typer.Exit(2)

    console.print(f"[yellow]Limited symbolic coverage explicitly allowed for:[/yellow] {names}")
    for item in limited:
        console.print(f"[yellow]- {item['pass_name']}: symbolic confidence={item['confidence']}[/yellow]")


def _limited_symbolic_passes(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None,
) -> list[dict[str, str]]:
    """Return passes that declare symbolic support as limited."""
    limited = []
    for mutation_name, mutation_pass in _selected_mutation_passes(mutations, config, seed=seed):
        symbolic_support = mutation_pass.get_support().validator_capabilities.get("symbolic", {})
        if symbolic_support.get("recommended") is False:
            limited.append(
                {
                    "mutation": mutation_name,
                    "pass_name": mutation_pass.name,
                    "confidence": str(symbolic_support.get("confidence", "unknown")),
                }
            )
    return limited


def _resolve_validation_mode(
    *,
    requested_mode: str,
    mutations: list[str],
    config: EngineConfig,
    seed: int | None,
    allow_limited_symbolic: bool,
    limited_symbolic_policy: str,
) -> tuple[str, dict[str, object] | None]:
    """Resolve requested vs effective validation mode for limited symbolic passes."""
    if requested_mode != "symbolic":
        return requested_mode, None

    limited = _limited_symbolic_passes(mutations, config, seed=seed)
    if not limited:
        return requested_mode, None

    if allow_limited_symbolic:
        names = ", ".join(item["pass_name"] for item in limited)
        console.print(f"[yellow]Limited symbolic coverage explicitly allowed for:[/yellow] {names}")
        for item in limited:
            console.print(f"[yellow]- {item['pass_name']}: symbolic confidence={item['confidence']}[/yellow]")
        return requested_mode, {
            "requested_mode": requested_mode,
            "effective_mode": requested_mode,
            "policy": "allow",
            "reason": "explicit-override",
            "limited_passes": limited,
        }

    if limited_symbolic_policy == "degrade-runtime":
        names = ", ".join(item["pass_name"] for item in limited)
        console.print(f"[yellow]Limited symbolic support detected for:[/yellow] {names}")
        console.print("[yellow]Degrading validation mode from symbolic to runtime.[/yellow]")
        return "runtime", {
            "requested_mode": requested_mode,
            "effective_mode": "runtime",
            "policy": limited_symbolic_policy,
            "reason": "limited-symbolic-support",
            "limited_passes": limited,
        }

    if limited_symbolic_policy == "degrade-structural":
        names = ", ".join(item["pass_name"] for item in limited)
        console.print(f"[yellow]Limited symbolic support detected for:[/yellow] {names}")
        console.print("[yellow]Degrading validation mode from symbolic to structural.[/yellow]")
        return "structural", {
            "requested_mode": requested_mode,
            "effective_mode": "structural",
            "policy": limited_symbolic_policy,
            "reason": "limited-symbolic-support",
            "limited_passes": limited,
        }

    _warn_or_block_limited_symbolic(
        mutations,
        config,
        seed=seed,
        allow_limited_symbolic=allow_limited_symbolic,
    )
    return requested_mode, None


def _print_mutation_summary(result: dict[str, object], output_path: Path | None = None) -> None:
    table = Table(title="Mutation Engine Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    requested_mode = result.get("requested_validation_mode", result.get("validation_mode", "off"))
    effective_mode = result.get("validation_mode", "off")
    table.add_row("Requested Validation", str(requested_mode))
    table.add_row("Effective Validation", str(effective_mode))
    table.add_row("Total Mutations", str(result.get("total_mutations", 0)))
    table.add_row("Passes Run", str(result.get("passes_run", 0)))
    table.add_row("Rolled Back Passes", str(result.get("rolled_back_passes", 0)))
    table.add_row("Discarded Mutations", str(result.get("discarded_mutations", 0)))
    table.add_row(
        "Validation Passed",
        "yes" if result.get("validation", {}).get("all_passed", False) else "no",
    )
    total_issues = result.get("validation", {}).get("total_issues", 0)
    table.add_row("Validation Issues", str(total_issues))
    for pass_name, pass_result in result.get("pass_results", {}).items():
        if "error" in pass_result:
            table.add_row(pass_name, f"[red]Error: {pass_result['error']}[/red]")
            continue
        rolled_back = ""
        if pass_result.get("rolled_back"):
            reason = pass_result.get("rollback_reason", "rollback")
            rolled_back = f" (rolled back: {reason})"
        table.add_row(
            pass_name,
            f"{pass_result.get('mutations_applied', 0)} mutations{rolled_back}",
        )

    console.print(table)
    if output_path is not None:
        console.print(f"\n[bold green]✓[/bold green] Binary saved to: {output_path}")


def _run_simple_mode(
    input_file: Path,
    output_file: Path | None,
    *,
    aggressive: bool,
    force: bool,
    seed: int | None,
    verbose: bool,
    debug: bool,
) -> None:
    setup_logging("DEBUG" if (verbose or debug) else "INFO")

    if output_file is None:
        output_file = input_file.parent / f"{input_file.stem}_morphed{input_file.suffix}"

    mode_str = "[bold red]AGGRESSIVE[/bold red]" if aggressive else "[bold green]STANDARD[/bold green]"
    force_str = " [bold yellow](FORCE)[/bold yellow]" if force else ""
    console.print(f"[bold green]r2morph - Simple Mode ({mode_str}{force_str})[/bold green]")
    console.print(f"Input:  {input_file}")
    console.print(f"Output: {output_file}")
    console.print("Applying stable mutations: [cyan]nop, substitute, register[/cyan]\n")

    with console.status("[bold green]Transforming binary..."):
        with MorphEngine(config={"seed": seed, "requested_mutations": ["nop", "substitute", "register"]}) as engine:
            engine.load_binary(input_file).analyze()
            config = _build_config(aggressive, force)
            _add_mutations(engine, ["nop", "substitute", "register"], config, seed=seed)

            report_path = output_file.parent / f"{output_file.stem}.report.json"
            result = engine.run(
                validation_mode="structural",
                rollback_policy="skip-invalid-pass",
                report_path=report_path,
                seed=seed,
            )

            engine.save(output_file)

        _print_mutation_summary(result, output_file)
        console.print(f"[cyan]Report:[/cyan] {report_path}")


@app.callback()
def main_callback(
    ctx: typer.Context,
    input_opt: Path | None = typer.Option(None, "--input", "-i", help="Input binary file (alternative style)"),
    output_opt: Path | None = typer.Option(None, "--output", "-o", help="Output binary file (alternative style)"),
    aggressive: bool = typer.Option(
        False, "--aggressive", "-a", help="Aggressive mode: more mutations, higher probability"
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Force mutations to be different from original"),
    seed: int | None = typer.Option(None, "--seed", help="Deterministic seed for stable mutation selection"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug output"),
):
    """
    r2morph - mutation engine with validation

    SIMPLE USAGE (like r2morph):
        r2morph input.exe [output.exe]
        r2morph -i input.exe -o output.exe

    This applies the stable mutation set:
    nop + substitute + register, then validates and writes a report.

    AGGRESSIVE MODE:
        r2morph -i input.exe -o output.exe --aggressive
        r2morph input.exe output.exe -a

    ADVANCED USAGE:
        r2morph analyze input.exe
        r2morph functions input.exe
        r2morph morph input.exe -m nop
    """
    if ctx.invoked_subcommand is not None:
        return

    input_file = input_opt
    output_file = output_opt
    positional = [arg for arg in ctx.args if not arg.startswith("-")]
    if input_file is None and positional:
        input_file = Path(positional[0])
        if len(positional) > 1:
            output_file = Path(positional[1])

    if input_file is None:
        console.print("[yellow]No input file provided.[/yellow]")
        console.print("\nUsage:")
        console.print("  Simple:   [cyan]r2morph input.exe [output.exe][/cyan]")
        console.print("  Alternative:   [cyan]r2morph -i input.exe -o output.exe[/cyan]")
        console.print("  Aggressive: [cyan]r2morph -i input.exe -o output.exe --aggressive[/cyan]")
        console.print("\nRun [cyan]r2morph --help[/cyan] for more options")
        raise typer.Exit(0)

    try:
        _run_simple_mode(
            input_file,
            output_file,
            aggressive=aggressive,
            force=force,
            seed=seed,
            verbose=verbose,
            debug=debug,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if verbose or debug:
            import traceback

            console.print(traceback.format_exc())
        raise typer.Exit(1)


@app.command()
def analyze(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """
    Analyze a binary and display statistics.
    """
    setup_logging("DEBUG" if verbose else "INFO")

    with console.status("[bold green]Analyzing binary..."):
        try:
            BinaryAnalyzer = _load_binary_analyzer()
            with MorphEngine() as engine:
                engine.load_binary(binary).analyze()
                analyzer = BinaryAnalyzer(engine.binary)
                stats = analyzer.get_statistics()

            table = Table(title=f"Binary Analysis: {binary.name}")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            arch = stats["architecture"]
            table.add_row("Architecture", f"{arch['arch']} ({arch['bits']}-bit)")
            table.add_row("Format", arch["format"])
            table.add_row("Endian", arch["endian"])
            table.add_row("Total Functions", str(stats["total_functions"]))
            table.add_row("Total Instructions", str(stats["total_instructions"]))
            table.add_row("Total Basic Blocks", str(stats["total_basic_blocks"]))
            table.add_row("Total Code Size", f"{stats['total_code_size']} bytes")
            table.add_row("Avg Function Size", f"{stats['avg_function_size']:.2f} bytes")
            table.add_row(
                "Avg Instructions/Function",
                f"{stats['avg_instructions_per_function']:.2f}",
            )

            console.print(table)

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)


@experimental_app.command("analyze-enhanced")
def analyze_enhanced(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    detect_only: bool = typer.Option(False, "--detect-only", help="Only run obfuscation detection"),
    symbolic: bool = typer.Option(False, "--symbolic", help="Enable symbolic execution analysis"),
    dynamic: bool = typer.Option(False, "--dynamic", help="Enable dynamic instrumentation"),
    devirt: bool = typer.Option(False, "--devirt", help="Enable devirtualization analysis"),
    iterative: bool = typer.Option(False, "--iterative", help="Enable iterative simplification"),
    rewrite: bool = typer.Option(False, "--rewrite", help="Enable binary rewriting"),
    bypass: bool = typer.Option(False, "--bypass", help="Enable anti-analysis bypass"),
    output: Path = typer.Option(None, "--output", "-o", help="Output directory for results"),
):
    """
    Experimental analysis for obfuscated binaries (secondary workflow).
    Requires enhanced dependencies: pip install 'r2morph[enhanced]'

    Phase 2 capabilities include:
    - Advanced packer detection (20+ packers)
    - Control Flow Obfuscation simplification
    - Iterative multi-pass simplification
    - Binary rewriting and reconstruction
    - Anti-analysis bypass framework
    """
    setup_logging("DEBUG" if verbose else "INFO")

    from r2morph.analysis.enhanced_analyzer import (
        EnhancedAnalysisOrchestrator,
        AnalysisOptions,
        check_enhanced_dependencies,
    )

    if not check_enhanced_dependencies():
        console.print("[bold red]Error:[/bold red] Enhanced analysis requires additional dependencies.")
        console.print("Install with: [cyan]pip install 'r2morph[enhanced]'[/cyan]")
        raise typer.Exit(1)

    with console.status("[bold green]Analyzing obfuscated binary..."):
        try:
            # Configure analysis options
            options = AnalysisOptions(
                verbose=verbose,
                detect_only=detect_only,
                symbolic=symbolic,
                dynamic=dynamic,
                devirt=devirt,
                iterative=iterative,
                rewrite=rewrite,
                bypass=bypass,
            )

            # Create and run the orchestrator
            orchestrator = EnhancedAnalysisOrchestrator(
                binary_path=binary,
                output_dir=output,
                console=console,
            )

            orchestrator.analyze(options)

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            if verbose:
                import traceback

                console.print(traceback.format_exc())
            raise typer.Exit(1)


@app.command()
def functions(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum functions to display"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """
    List functions in a binary.
    """
    setup_logging("DEBUG" if verbose else "INFO")

    with console.status("[bold green]Loading binary..."):
        try:
            BinaryAnalyzer = _load_binary_analyzer()
            with MorphEngine() as engine:
                engine.load_binary(binary).analyze()
                analyzer = BinaryAnalyzer(engine.binary)
                funcs = analyzer.get_functions_list()

            table = Table(title=f"Functions in {binary.name}")
            table.add_column("Address", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Size", style="yellow")
            table.add_column("Instructions", style="magenta")

            for func in funcs[:limit]:
                table.add_row(
                    f"0x{func.address:x}",
                    func.name,
                    str(func.size),
                    str(func.get_instructions_count()),
                )

            console.print(table)

            if len(funcs) > limit:
                console.print(
                    f"\n[yellow]Showing {limit} of {len(funcs)} functions. Use --limit to show more.[/yellow]"
                )

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)


@app.command()
def morph(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
    output: Path = typer.Option(None, "--output", "-o", help="Output path for morphed binary"),
    mutations: list[str] = typer.Option(
        ["nop", "substitute", "register"],
        "--mutation",
        "-m",
        help="Mutations to apply (stable: nop, substitute, register; experimental: expand, block)",
    ),
    aggressive: bool = typer.Option(False, "--aggressive", "-a", help="Aggressive mode: more mutations"),
    force: bool = typer.Option(False, "--force", "-f", help="Force mutations to be different from original"),
    validation_mode: str = typer.Option(
        "structural",
        "--validation-mode",
        help="Validation mode: structural, runtime, symbolic, off",
    ),
    allow_limited_symbolic: bool = typer.Option(
        False,
        "--allow-limited-symbolic",
        help="Allow symbolic mode for passes that declare limited symbolic support",
    ),
    limited_symbolic_policy: str = typer.Option(
        "block",
        "--limited-symbolic-policy",
        help="How to handle limited symbolic passes: block, degrade-runtime, degrade-structural",
    ),
    rollback_policy: str = typer.Option(
        "skip-invalid-pass",
        "--rollback-policy",
        help="Rollback policy: fail-fast, skip-invalid-pass, skip-invalid-mutation",
    ),
    report: Path | None = typer.Option(
        None,
        "--report",
        help="Write a machine-readable JSON report",
    ),
    runtime_corpus: Path | None = typer.Option(
        None,
        "--runtime-corpus",
        help="Optional JSON corpus for runtime validation during mutate",
    ),
    runtime_compare_files: bool = typer.Option(
        False,
        "--runtime-compare-files",
        help="Compare monitored files during runtime validation",
    ),
    runtime_normalize_whitespace: bool = typer.Option(
        False,
        "--runtime-normalize-whitespace",
        help="Ignore trailing whitespace differences during runtime validation",
    ),
    runtime_timeout: int = typer.Option(
        10,
        "--runtime-timeout",
        help="Timeout per runtime validation test case in seconds",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Fail with code 1 unless the final report contains at least one pass at or above: mismatch, without-coverage, bounded-only, clean, not-requested",
    ),
    require_pass_severity: list[str] = typer.Option(
        None,
        "--require-pass-severity",
        help="Require a specific pass severity in the final report, e.g. InstructionSubstitution=bounded-only",
    ),
    seed: int | None = typer.Option(None, "--seed", help="Deterministic seed for mutation selection"),
    cache: bool = typer.Option(
        False,
        "--cache",
        help="Enable analysis caching for faster repeated runs",
    ),
    clear_cache: bool = typer.Option(
        False,
        "--clear-cache",
        help="Clear the analysis cache before running",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """
    Apply tracked mutations to a binary and validate the result.

    Examples:
        r2morph mutate binary.exe -o output.exe
        r2morph mutate binary.exe -m nop -m substitute --report report.json
        r2morph mutate binary.exe --cache  # Enable caching for faster repeated runs
    """
    setup_logging("DEBUG" if verbose else "INFO")

    if not output:
        output = binary.parent / f"{binary.stem}_morphed{binary.suffix}"

    if clear_cache:
        from r2morph.core.analysis_cache import AnalysisCache

        cache_instance = AnalysisCache()
        cleared = cache_instance.clear()
        console.print(f"[cyan]Cleared {cleared} cache entries[/cyan]")

    unknown = [mutation for mutation in mutations if mutation not in SUPPORTED_MUTATIONS | EXPERIMENTAL_MUTATIONS]
    if unknown:
        console.print(f"[bold red]Error:[/bold red] Unknown mutations: {', '.join(unknown)}")
        raise typer.Exit(2)

    mode_str = "[bold red]AGGRESSIVE[/bold red]" if aggressive else "[bold green]STANDARD[/bold green]"
    console.print(f"[bold green]Starting mutation pipeline ({mode_str})[/bold green]")
    console.print(f"Input:  {binary}")
    console.print(f"Output: {output}")
    console.print(f"Mutations: {', '.join(mutations)}\n")

    experimental = [mutation for mutation in mutations if is_experimental_mutation(mutation)]
    _warn_experimental_mutations(experimental)
    _warn_experimental_validation_mode(validation_mode)
    _, min_severity_rank = _resolve_min_severity(min_severity)
    config = _build_config(aggressive, force)
    pass_severity_requirements = _resolve_pass_severity_requirements(
        require_pass_severity,
        alias_map=_mutation_pass_alias_map(config, seed=seed),
    )
    effective_validation_mode, validation_policy = _resolve_validation_mode(
        requested_mode=validation_mode,
        mutations=mutations,
        config=config,
        seed=seed,
        allow_limited_symbolic=allow_limited_symbolic,
        limited_symbolic_policy=limited_symbolic_policy,
    )

    with console.status("[bold green]Transforming binary..."):
        try:
            with MorphEngine(
                config={
                    "seed": seed,
                    "requested_mutations": list(mutations),
                    "experimental_mutations": experimental,
                    "requested_validation_mode": validation_mode,
                    "effective_validation_mode": effective_validation_mode,
                    "validation_policy": validation_policy,
                }
            ) as engine:
                engine.load_binary(binary).analyze()
                _add_mutations(engine, mutations, config, seed=seed)

                runtime_validator = None
                if effective_validation_mode == "runtime":
                    runtime_validator = _build_runtime_validator(
                        timeout=runtime_timeout,
                        corpus=runtime_corpus,
                        compare_files=runtime_compare_files,
                        normalize_whitespace=runtime_normalize_whitespace,
                    )

                report_path = report or output.parent / f"{output.stem}.report.json"
                result = engine.run(
                    validation_mode=effective_validation_mode,
                    rollback_policy=rollback_policy,
                    checkpoint_per_mutation=rollback_policy == "skip-invalid-mutation",
                    runtime_validator=runtime_validator,
                    runtime_validate_per_pass=effective_validation_mode == "runtime",
                    report_path=report_path,
                    seed=seed,
                )

                engine.save(output)

            _print_mutation_summary(result, output)
            console.print(f"[cyan]Report:[/cyan] {report_path}")
            report_payload = engine.build_report(result)
            severity_rows = list(report_payload.get("summary", {}).get("symbolic_severity_by_pass", []))
            min_severity_passed = _severity_threshold_met(severity_rows, min_severity_rank)
            pass_requirements_ok = True
            pass_requirement_failures: list[str] = []
            if pass_severity_requirements:
                pass_requirements_ok, pass_requirement_failures = _pass_severity_requirements_met(
                    severity_rows,
                    pass_severity_requirements,
                )
            report_payload = _attach_gate_evaluation(
                report_payload,
                min_severity=min_severity,
                min_severity_passed=min_severity_passed,
                require_pass_severity=pass_severity_requirements,
                require_pass_severity_passed=pass_requirements_ok,
                require_pass_severity_failures=pass_requirement_failures,
            )
            if report_path is not None:
                report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
            if min_severity is not None:
                if min_severity_passed:
                    console.print(f"[cyan]Severity gate passed:[/cyan] min_severity={min_severity}")
                else:
                    console.print(f"[bold yellow]Severity gate failed:[/bold yellow] min_severity={min_severity}")
                    raise typer.Exit(1)
            if pass_severity_requirements:
                if pass_requirements_ok:
                    console.print(
                        "[cyan]Pass severity gate passed:[/cyan] "
                        + ", ".join(
                            f"{pass_name}<={severity}" for pass_name, severity, _rank in pass_severity_requirements
                        )
                    )
                else:
                    console.print(
                        "[bold yellow]Pass severity gate failed:[/bold yellow] " + ", ".join(pass_requirement_failures)
                    )
                    raise typer.Exit(1)

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)


@app.command(name="mutate")
def mutate(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
    output: Path = typer.Option(None, "--output", "-o", help="Output path for morphed binary"),
    mutations: list[str] = typer.Option(
        ["nop", "substitute", "register"],
        "--mutation",
        "-m",
        help="Mutations to apply (stable: nop, substitute, register; experimental: expand, block)",
    ),
    aggressive: bool = typer.Option(False, "--aggressive", "-a", help="Aggressive mode: more mutations"),
    force: bool = typer.Option(False, "--force", "-f", help="Force mutations to be different from original"),
    validation_mode: str = typer.Option(
        "structural",
        "--validation-mode",
        help="Validation mode: structural, runtime, symbolic, off",
    ),
    allow_limited_symbolic: bool = typer.Option(
        False,
        "--allow-limited-symbolic",
        help="Allow symbolic mode for passes that declare limited symbolic support",
    ),
    limited_symbolic_policy: str = typer.Option(
        "block",
        "--limited-symbolic-policy",
        help="How to handle limited symbolic passes: block, degrade-runtime, degrade-structural",
    ),
    rollback_policy: str = typer.Option(
        "skip-invalid-pass",
        "--rollback-policy",
        help="Rollback policy: fail-fast, skip-invalid-pass, skip-invalid-mutation",
    ),
    report: Path | None = typer.Option(
        None,
        "--report",
        help="Write a machine-readable JSON report",
    ),
    runtime_corpus: Path | None = typer.Option(
        None,
        "--runtime-corpus",
        help="Optional JSON corpus for runtime validation during mutate",
    ),
    runtime_compare_files: bool = typer.Option(
        False,
        "--runtime-compare-files",
        help="Compare monitored files during runtime validation",
    ),
    runtime_normalize_whitespace: bool = typer.Option(
        False,
        "--runtime-normalize-whitespace",
        help="Ignore trailing whitespace differences during runtime validation",
    ),
    runtime_timeout: int = typer.Option(
        10,
        "--runtime-timeout",
        help="Timeout per runtime validation test case in seconds",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Fail with code 1 unless the final report contains at least one pass at or above: mismatch, without-coverage, bounded-only, clean, not-requested",
    ),
    require_pass_severity: list[str] = typer.Option(
        None,
        "--require-pass-severity",
        help="Require a specific pass severity in the final report, e.g. InstructionSubstitution=bounded-only",
    ),
    seed: int | None = typer.Option(None, "--seed", help="Deterministic seed for mutation selection"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """Alias for `morph` using the product-oriented command name."""
    return morph(
        binary=binary,
        output=output,
        mutations=mutations,
        aggressive=aggressive,
        force=force,
        validation_mode=validation_mode,
        allow_limited_symbolic=allow_limited_symbolic,
        limited_symbolic_policy=limited_symbolic_policy,
        rollback_policy=rollback_policy,
        report=report,
        runtime_corpus=runtime_corpus,
        runtime_compare_files=runtime_compare_files,
        runtime_normalize_whitespace=runtime_normalize_whitespace,
        runtime_timeout=runtime_timeout,
        min_severity=min_severity,
        require_pass_severity=require_pass_severity,
        seed=seed,
        verbose=verbose,
    )


@app.command()
def validate(
    original: Path = typer.Argument(..., help="Original binary", exists=True),
    mutated: Path = typer.Argument(..., help="Mutated binary", exists=True),
    corpus: Path | None = typer.Option(
        None,
        "--corpus",
        help="Optional JSON corpus describing runtime test cases (see dataset/runtime_corpus.json)",
    ),
    compare_files: bool = typer.Option(
        False,
        "--compare-files",
        help="Compare monitored output files in addition to stdout/stderr/exitcode",
    ),
    normalize_whitespace: bool = typer.Option(
        False,
        "--normalize-whitespace",
        help="Ignore trailing whitespace differences in stdout/stderr",
    ),
    timeout: int = typer.Option(10, "--timeout", help="Timeout per test case in seconds"),
):
    """
    Run runtime validation for an original/mutated binary pair.

    Corpus schema:
        [
          {
            "description": "default-exec",
            "args": [],
            "stdin": "",
            "expected_exitcode": 0,
            "env": {},
            "working_dir": null,
            "monitored_files": []
          }
        ]
    """
    validator = _build_runtime_validator(
        timeout=timeout,
        corpus=corpus,
        compare_files=compare_files,
        normalize_whitespace=normalize_whitespace,
    )
    result = validator.validate(original, mutated)
    console.print_json(json.dumps(result.to_dict()))
    raise typer.Exit(0 if result.passed else 1)


@app.command()
def diff(
    original: Path = typer.Argument(..., help="Original binary", exists=True),
    mutated: Path = typer.Argument(..., help="Mutated binary", exists=True),
):
    """
    Show a lightweight diff summary between two binaries.
    """
    DiffAnalyzer = _load_diff_analyzer()
    analyzer = DiffAnalyzer()
    result = analyzer.compare(original, mutated)
    console.print_json(json.dumps(result.__dict__))
    raise typer.Exit(0)


@app.command()
def report(
    report_file: Path = typer.Argument(..., help="Report JSON generated by mutate", exists=True),
    only_pass: str | None = typer.Option(
        None,
        "--only-pass",
        help="Show only mutations produced by the specified pass name",
    ),
    only_status: str | None = typer.Option(
        None,
        "--only-status",
        help="Show only mutations with the specified symbolic_status",
    ),
    only_mismatches: bool = typer.Option(
        False,
        "--only-mismatches",
        help="Show only mutations with symbolic observable mismatches",
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        help="Show only the textual summary without printing report JSON",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the filtered report JSON to a file",
    ),
    require_results: bool = typer.Option(
        False,
        "--require-results",
        help="Exit with code 1 when the filtered view contains no mutations",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Require at least one pass with severity: mismatch, without-coverage, bounded-only, clean, not-requested",
    ),
    only_expected_severity: str | None = typer.Option(
        None,
        "--only-expected-severity",
        help="Filter persisted gate failures by expected severity: mismatch, without-coverage, bounded-only, clean, not-requested",
    ),
    only_pass_failure: str | None = typer.Option(
        None,
        "--only-pass-failure",
        help="Filter persisted gate failures to a specific pass name",
    ),
    only_degraded: bool = typer.Option(
        False,
        "--only-degraded",
        help="Show/report only executions where requested and effective validation modes differ",
    ),
    only_failed_gates: bool = typer.Option(
        False,
        "--only-failed-gates",
        help="Show/report only executions where persisted CLI gate evaluation failed",
    ),
    only_risky_passes: bool = typer.Option(
        False,
        "--only-risky-passes",
        help="Show/report only passes with symbolic mismatches, structural issues, or non-clean symbolic severity",
    ),
    only_structural_risk: bool = typer.Option(
        False,
        "--only-structural-risk",
        help="Show/report only passes with structural issues",
    ),
    only_symbolic_risk: bool = typer.Option(
        False,
        "--only-symbolic-risk",
        help="Show/report only passes with symbolic mismatches or non-clean symbolic severity",
    ),
    only_clean_passes: bool = typer.Option(
        False,
        "--only-clean-passes",
        help="Show/report only passes with no structural issues and clean symbolic evidence",
    ),
    only_covered_passes: bool = typer.Option(
        False,
        "--only-covered-passes",
        help="Show/report only clean passes with effective symbolic coverage",
    ),
    only_uncovered_passes: bool = typer.Option(
        False,
        "--only-uncovered-passes",
        help="Show/report only clean passes without effective symbolic coverage",
    ),
    output_format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format: json (default) or sarif",
    ),
):
    """
    Display a previously generated engine report.
    """
    if output_format.lower() == "sarif":
        from r2morph.reporting.sarif_formatter import format_as_sarif

    with open(report_file, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    context = _resolve_report_context(
        payload=payload,
        only_pass=only_pass,
        only_pass_failure=only_pass_failure,
        only_expected_severity=only_expected_severity,
    )
    summary = context["summary"]
    resolved_only_pass = context["resolved_only_pass"]
    resolved_only_pass_failure = context["resolved_only_pass_failure"]
    requested_validation_mode = context["requested_validation_mode"]
    effective_validation_mode = context["effective_validation_mode"]
    validation_policy = context["validation_policy"]
    gate_evaluation = context["gate_evaluation"]
    gate_requested = context["gate_requested"]
    gate_results = context["gate_results"]
    gate_failure_summary = context["gate_failure_summary"]
    gate_failure_priority = context["gate_failure_priority"]
    gate_failure_severity_priority = context["gate_failure_severity_priority"]
    failed_gates = context["failed_gates"]
    degraded_validation = context["degraded_validation"]
    degraded_passes = context["degraded_passes"]

    pass_results = payload.get("passes", {})
    general_state = _resolve_general_report_flow_state(
        payload=payload,
        summary=summary,
        pass_results=pass_results,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        degraded_passes=degraded_passes,
        failed_gates=failed_gates,
        validation_policy=validation_policy,
        gate_evaluation=gate_evaluation,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
    )
    _, min_severity_rank = _resolve_min_severity(min_severity)
    dispatch_state = _build_report_dispatch_state(
        context=context,
        general_state=general_state,
        payload=payload,
        pass_results=pass_results,
        only_pass=only_pass,
        only_pass_failure=only_pass_failure,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        output=output,
        summary_only=summary_only,
        require_results=require_results,
        min_severity=min_severity,
        min_severity_rank=min_severity_rank,
        only_expected_severity=only_expected_severity,
        only_mismatches=only_mismatches,
    )
    if output_format.lower() == "sarif":
        from r2morph.reporting.sarif_formatter import format_as_sarif

        sarif_report = format_as_sarif(payload)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(sarif_report)
            rprint(f"[green]SARIF report written to[/green] {output}")
        else:
            print(sarif_report)
        return

    _dispatch_report_flow(**dispatch_state)


@app.command()
def version():
    """
    Display version information.
    """
    rprint(f"[bold cyan]r2morph[/bold cyan] version [green]{__version__}[/green]")
    rprint("Metamorphic mutation engine with validation")


@app.command()
def cache(
    clear: bool = typer.Option(False, "--clear", "-c", help="Clear all cached analysis results"),
    stats: bool = typer.Option(False, "--stats", "-s", help="Show cache statistics"),
    path: Path | None = typer.Option(None, "--path", "-p", help="Custom cache directory path"),
):
    """
    Manage the analysis cache.

    Examples:
        r2morph cache --stats          # Show cache statistics
        r2morph cache --clear          # Clear all cached data
        r2morph cache --clear --path /custom/cache  # Clear specific cache directory
    """
    from r2morph.core.analysis_cache import AnalysisCache

    cache_dir = path if path else None
    cache_instance = AnalysisCache(cache_dir=cache_dir)

    if stats:
        statistics = cache_instance.get_stats()
        console.print(f"[cyan]Cache Statistics:[/cyan]")
        console.print(f"  Hits: {statistics.hits}")
        console.print(f"  Misses: {statistics.misses}")
        console.print(f"  Hit Rate: {statistics.hit_rate:.2%}")
        console.print(f"  Entries: {statistics.entry_count}")
        console.print(f"  Size: {statistics.total_size_bytes / (1024 * 1024):.2f} MB")
        if statistics.oldest_entry:
            console.print(f"  Oldest Entry: {statistics.oldest_entry.isoformat()}")
        if statistics.newest_entry:
            console.print(f"  Newest Entry: {statistics.newest_entry.isoformat()}")
        return

    if clear:
        cleared = cache_instance.clear()
        console.print(f"[green]Cleared {cleared} cache entries[/green]")
        return

    console.print("[yellow]Specify --clear or --stats[/yellow]")
    raise typer.Exit(1)


def main():
    """Entry point for the CLI."""
    argv = sys.argv[1:]
    if argv and not argv[0].startswith("-") and argv[0] not in KNOWN_COMMANDS:
        parser = argparse.ArgumentParser(prog="r2morph")
        parser.add_argument("input_file")
        parser.add_argument("output_file", nargs="?")
        parser.add_argument("-i", "--input", dest="input_opt")
        parser.add_argument("-o", "--output", dest="output_opt")
        parser.add_argument("-a", "--aggressive", action="store_true")
        parser.add_argument("-f", "--force", action="store_true")
        parser.add_argument("--seed", type=int)
        parser.add_argument("-v", "--verbose", action="store_true")
        parser.add_argument("-d", "--debug", action="store_true")
        args = parser.parse_args(argv)
        input_file = Path(args.input_opt or args.input_file)
        output_file = Path(args.output_opt or args.output_file) if (args.output_opt or args.output_file) else None
        _run_simple_mode(
            input_file,
            output_file,
            aggressive=args.aggressive,
            force=args.force,
            seed=args.seed,
            verbose=args.verbose,
            debug=args.debug,
        )
        return
    app()


if __name__ == "__main__":
    main()
