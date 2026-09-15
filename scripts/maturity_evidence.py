#!/usr/bin/env python3
"""Aggregate per-pass maturity evidence without promoting partial results."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import defusedxml.ElementTree

_COMPOSITION_PARAMETER_MAP = {
    "antidisassembly": "AntiDisassembly",
    "apihashing": "APIHashing",
    "codemobility": "CodeMobility",
    "dataflowmutation": "DataFlowMutation",
    "functionoutlining": "FunctionOutlining",
    "importobfuscation": "ImportObfuscation",
    "opaquepredicates": "OpaquePredicates",
    "polymorphicengine": "PolymorphicEngine",
    "selfmodifyingcode": "SelfModifyingCode",
    "shortjumppatching": "ShortJumpPatching",
    "stackstrings": "StackStrings",
    "stringobfuscation": "StringObfuscation",
}
_COMPOSITION_PARAMETER_RE = re.compile(r"\[([^\]]+)\]")
_SIMPLE_COMPOSITION_LABELS = {
    "nop": "NopInsertion",
    "substitution": "InstructionSubstitution",
    "constant": "ConstantUnfolding",
}
_PERFORMANCE_FIELDS = (
    "output_size_coverage_percent",
    "transform_duration_coverage_percent",
    "runtime_duration_coverage_percent",
    "static_metric_coverage_percent",
)
_FULL_COVERAGE_PERCENT = 100.0


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON report must contain an object: {path}")
    return value


def _pass_names(report: Mapping[str, Any]) -> tuple[str, ...]:
    value = report.get("pass_names")
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("maturity report is missing pass_names")
    return tuple(value)


def _pass_summary(report: Mapping[str, Any], pass_name: str) -> Mapping[str, Any]:
    summaries = report.get("summary")
    if not isinstance(summaries, Mapping):
        raise ValueError("maturity report is missing summary")
    summary = summaries.get(pass_name)
    if not isinstance(summary, Mapping):
        raise ValueError(f"maturity report is missing summary for {pass_name}")
    return summary


def _composition_passes(test_name: str) -> set[str]:
    parameters = _COMPOSITION_PARAMETER_RE.findall(test_name)
    if parameters:
        parameter = parameters[-1].lower()
        if parameter in _COMPOSITION_PARAMETER_MAP:
            return {_COMPOSITION_PARAMETER_MAP[parameter]}
    lowered = test_name.lower()
    if "polymorphic_engine" in lowered:
        return {"PolymorphicEngine"}
    return {pass_name for token, pass_name in _SIMPLE_COMPOSITION_LABELS.items() if token in lowered}


def read_composition_evidence(paths: Iterable[Path]) -> dict[str, Any]:
    """Merge composition JUnit reports while retaining test-level counts."""
    reports = tuple(paths)
    if not reports:
        raise ValueError("at least one composition report is required")
    pass_counts: dict[str, int] = {}
    case_count = failure_count = error_count = skipped_count = 0
    for path in reports:
        root = defusedxml.ElementTree.parse(path).getroot()
        cases = root.findall(".//testcase")
        case_count += len(cases)
        failure_count += len(root.findall(".//failure"))
        error_count += len(root.findall(".//error"))
        skipped_count += len(root.findall(".//skipped"))
        for case in cases:
            for pass_name in _composition_passes(case.attrib.get("name", "")):
                pass_counts[pass_name] = pass_counts.get(pass_name, 0) + 1
    return {
        "report_count": len(reports),
        "case_count": case_count,
        "failure_count": failure_count,
        "error_count": error_count,
        "skipped_count": skipped_count,
        "pass_case_counts": dict(sorted(pass_counts.items())),
    }


def _performance_evidence(summary: Mapping[str, Any]) -> dict[str, Any]:
    coverage = {field: summary.get(field) for field in _PERFORMANCE_FIELDS}
    complete = all(value == _FULL_COVERAGE_PERCENT for value in coverage.values())
    return {"status": "complete" if complete else "incomplete", "coverage": coverage}


def _behavioral_evidence(summary: Mapping[str, Any]) -> dict[str, Any]:
    applied = summary.get("applied_runs", 0)
    missing = summary.get("behavioral_validation_missing_observations", 0)
    rate = summary.get("behavioral_false_positive_rate_percent")
    complete = isinstance(applied, int) and applied > 0 and missing == 0 and isinstance(rate, int | float)
    return {
        "status": "measured" if complete else "incomplete",
        "observations": summary.get("behavioral_validation_observations", 0),
        "false_positive_observations": summary.get("behavioral_false_positive_observations", 0),
        "false_positive_rate_percent": rate,
        "missing_observations": missing,
    }


def _instruction_evidence(summary: Mapping[str, Any]) -> dict[str, Any]:
    applied = summary.get("affected_instruction_applied_runs", 0)
    missing = summary.get("affected_instruction_missing_runs", 0)
    complete = isinstance(applied, int) and applied > 0 and missing == 0
    return {
        "status": "measured" if complete else "incomplete",
        "applied_runs": applied,
        "missing_runs": missing,
        "mnemonics": summary.get("affected_instruction_mnemonics", []),
        "record_count": summary.get("affected_instruction_record_count", 0),
    }


def _composition_status(pass_name: str, summary: Mapping[str, Any], composition: Mapping[str, Any]) -> dict[str, Any]:
    count = composition.get("pass_case_counts", {}).get(pass_name, 0)
    applied = summary.get("applied_runs", 0)
    complete = (
        isinstance(count, int)
        and count > 0
        and composition.get("failure_count") == 0
        and composition.get("error_count") == 0
        and composition.get("skipped_count") == 0
        and isinstance(applied, int)
        and applied > 0
    )
    status = "complete" if complete else "preview-only" if applied == 0 else "incomplete"
    return {"status": status, "case_count": count}


def _decompiler_evidence(
    pass_name: str,
    adversarial: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if adversarial is None:
        return {"status": "pending", "completed_tools": [], "incomplete_tools": []}
    summary = adversarial.get("summary")
    effectiveness = summary.get("analyzer_effectiveness_by_pass", {}) if isinstance(summary, Mapping) else {}
    tools = effectiveness.get(pass_name, {}) if isinstance(effectiveness, Mapping) else {}
    if not isinstance(tools, Mapping):
        return {"status": "pending", "completed_tools": [], "incomplete_tools": []}
    completed = sorted(
        name
        for name, value in tools.items()
        if isinstance(value, Mapping) and value.get("completion_percent") == _FULL_COVERAGE_PERCENT
    )
    incomplete = sorted(name for name in tools if name not in completed)
    status = "comparable" if not incomplete else "partial" if completed else "pending"
    return {"status": status, "completed_tools": completed, "incomplete_tools": incomplete}


def build_evidence(
    differential: Mapping[str, Any],
    extended: Mapping[str, Any],
    composition: Mapping[str, Any],
    adversarial: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a reviewable per-pass maturity evidence document."""
    names = tuple(dict.fromkeys((*_pass_names(differential), *_pass_names(extended))))
    passes: dict[str, Any] = {}
    for pass_name in names:
        source = extended if pass_name in _pass_names(extended) else differential
        summary = _pass_summary(source, pass_name)
        passes[pass_name] = {
            "performance": _performance_evidence(summary),
            "behavioral_false_positive": _behavioral_evidence(summary),
            "affected_instructions": _instruction_evidence(summary),
            "composition": _composition_status(pass_name, summary, composition),
            "decompiler": _decompiler_evidence(pass_name, adversarial),
        }
    blockers = {
        field: sorted(name for name, evidence in passes.items() if evidence[field]["status"] not in complete)
        for field, complete in (
            ("performance", {"complete"}),
            ("behavioral_false_positive", {"measured"}),
            ("affected_instructions", {"measured"}),
            ("composition", {"complete"}),
            ("decompiler", {"comparable"}),
        )
    }
    return {
        "schema_version": 1,
        "measurement": "protection-pass-maturity-evidence",
        "pass_names": list(names),
        "passes": passes,
        "summary": {
            "blockers": {field: values for field, values in blockers.items() if values},
            "blocker_totals": {field: len(values) for field, values in blockers.items()},
            "composition": dict(composition),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--differential", type=Path, required=True)
    parser.add_argument("--extended", type=Path, required=True)
    parser.add_argument("--composition-dir", type=Path, required=True)
    parser.add_argument("--adversarial", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    composition_paths = sorted(args.composition_dir.rglob("*.xml"))
    adversarial = _read_json(args.adversarial) if args.adversarial else None
    evidence = build_evidence(
        _read_json(args.differential),
        _read_json(args.extended),
        read_composition_evidence(composition_paths),
        adversarial,
    )
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
