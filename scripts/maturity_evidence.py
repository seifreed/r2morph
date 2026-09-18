#!/usr/bin/env python3
"""Aggregate per-pass maturity evidence without promoting partial results."""

from __future__ import annotations

import argparse
import importlib
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, cast

_DEFUSED_ELEMENT_TREE = cast(Any, importlib.import_module("defusedxml.ElementTree"))

_COMPOSITION_PARAMETER_MAP = {
    "antidisassembly": "AntiDisassembly",
    "apihashing": "APIHashing",
    "blockreordering": "BlockReordering",
    "codemobility": "CodeMobility",
    "codevirtualization": "CodeVirtualization",
    "controlflowflattening": "ControlFlowFlattening",
    "dataflowmutation": "DataFlowMutation",
    "deadcodeinjection": "DeadCodeInjection",
    "functionoutlining": "FunctionOutlining",
    "importobfuscation": "ImportObfuscation",
    "instructionexpansion": "InstructionExpansion",
    "opaquepredicates": "OpaquePredicates",
    "polymorphicengine": "PolymorphicEngine",
    "patternsubstitution": "PatternSubstitution",
    "registersubstitution": "RegisterSubstitution",
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
_SIMPLE_COMPOSITION_PAIR_RE = re.compile(
    r"\[(?P<first>nop|constant|substitution)_then_(?P<second>nop|constant|substitution)\]"
)
_PERFORMANCE_FIELDS = (
    "output_size_coverage_percent",
    "transform_duration_coverage_percent",
    "runtime_duration_coverage_percent",
    "static_metric_coverage_percent",
)
_FULL_COVERAGE_PERCENT = 100.0
_MIN_DIRECTIONAL_COMPOSITION_PAIRS = 2


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


def _composition_pairs(test_name: str) -> set[tuple[str, str]]:
    """Extract directional pass pairs from the real-fixture test names."""
    simple_match = _SIMPLE_COMPOSITION_PAIR_RE.search(test_name)
    if simple_match is not None:
        first = _SIMPLE_COMPOSITION_LABELS[simple_match.group("first")]
        second = _SIMPLE_COMPOSITION_LABELS[simple_match.group("second")]
        return {(first, second)}

    lowered = test_name.lower()
    parameters = _COMPOSITION_PARAMETER_RE.findall(test_name)
    if not parameters:
        return set()
    parameter = parameters[-1].lower()
    extended = _COMPOSITION_PARAMETER_MAP.get(parameter)
    if extended is None or "nop" not in lowered:
        return set()
    if "after_nop" in lowered:
        return {("NopInsertion", extended)}
    if "before_nop" in lowered:
        return {(extended, "NopInsertion")}
    return set()


def read_composition_evidence(paths: Iterable[Path]) -> dict[str, Any]:
    """Merge composition JUnit reports while retaining test-level counts."""
    reports = tuple(paths)
    if not reports:
        raise ValueError("at least one composition report is required")
    pass_counts: dict[str, int] = {}
    pair_counts: dict[str, int] = {}
    case_count = failure_count = error_count = skipped_count = 0
    for path in reports:
        root = _DEFUSED_ELEMENT_TREE.parse(path).getroot()
        cases = root.findall(".//testcase")
        case_count += len(cases)
        failure_count += len(root.findall(".//failure"))
        error_count += len(root.findall(".//error"))
        skipped_count += len(root.findall(".//skipped"))
        for case in cases:
            for pass_name in _composition_passes(case.attrib.get("name", "")):
                pass_counts[pass_name] = pass_counts.get(pass_name, 0) + 1
            for first, second in _composition_pairs(case.attrib.get("name", "")):
                pair = f"{first}->{second}"
                pair_counts[pair] = pair_counts.get(pair, 0) + 1
    return {
        "report_count": len(reports),
        "case_count": case_count,
        "failure_count": failure_count,
        "error_count": error_count,
        "skipped_count": skipped_count,
        "pass_case_counts": dict(sorted(pass_counts.items())),
        "pair_case_counts": dict(sorted(pair_counts.items())),
        "directional_pair_count": len(pair_counts),
    }


def _performance_evidence(summary: Mapping[str, Any]) -> dict[str, Any]:
    applied = summary.get("applied_runs", 0)
    coverage = {field: summary.get(field) for field in _PERFORMANCE_FIELDS}
    complete = (
        isinstance(applied, int) and applied > 0 and all(value == _FULL_COVERAGE_PERCENT for value in coverage.values())
    )
    return {"status": "complete" if complete else "incomplete", "coverage": coverage}


def _behavioral_evidence(summary: Mapping[str, Any]) -> dict[str, Any]:
    applied = summary.get("applied_runs", 0)
    missing = summary.get("behavioral_validation_missing_observations", 0)
    rate = summary.get("behavioral_false_positive_rate_percent")
    independent = summary.get("independent_semantic_observations", 0)
    independent_missing = summary.get("independent_semantic_missing_observations", 0)
    independent_rate = summary.get("independent_semantic_false_positive_rate_percent")
    complete = (
        isinstance(applied, int)
        and applied > 0
        and missing == 0
        and isinstance(rate, int | float)
        and isinstance(independent, int)
        and independent > 0
        and independent_missing == 0
        and isinstance(independent_rate, int | float)
    )
    return {
        "status": "measured" if complete else "incomplete",
        "observations": summary.get("behavioral_validation_observations", 0),
        "false_positive_observations": summary.get("behavioral_false_positive_observations", 0),
        "false_positive_rate_percent": rate,
        "missing_observations": missing,
        "independent_semantic_observations": independent,
        "independent_semantic_false_positive_observations": summary.get(
            "independent_semantic_false_positive_observations", 0
        ),
        "independent_semantic_false_positive_rate_percent": independent_rate,
        "independent_semantic_missing_observations": independent_missing,
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
    pair_counts = composition.get("pair_case_counts", {})
    directional_pairs = sorted(
        pair
        for pair, pair_count in pair_counts.items()
        if isinstance(pair, str) and isinstance(pair_count, int) and pair_count > 0 and pass_name in pair.split("->")
    )
    complete = (
        isinstance(count, int)
        and count > 0
        and composition.get("failure_count") == 0
        and composition.get("error_count") == 0
        and composition.get("skipped_count") == 0
        and isinstance(applied, int)
        and applied > 0
        and len(directional_pairs) >= _MIN_DIRECTIONAL_COMPOSITION_PAIRS
    )
    status = "complete" if complete else "preview-only" if applied == 0 else "incomplete"
    return {
        "status": status,
        "case_count": count,
        "directional_pair_count": len(directional_pairs),
        "directional_pairs": directional_pairs,
    }


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
    observed_tools = {
        name: value
        for name, value in tools.items()
        if isinstance(value, Mapping)
        and isinstance(value.get("decompiler"), Mapping)
        and value["decompiler"].get("observed_pairs", 0) > 0
    }
    completed = sorted(
        name
        for name, value in observed_tools.items()
        if value["decompiler"].get("completion_percent") == _FULL_COVERAGE_PERCENT
    )
    incomplete = sorted(name for name in observed_tools if name not in completed)
    status = "comparable" if not incomplete else "partial" if completed else "pending"
    return {
        "status": status if completed else "pending",
        "completed_tools": completed,
        "incomplete_tools": incomplete,
        "observed_tools": sorted(observed_tools),
        "non_decompiler_tools": sorted(name for name in tools if name not in observed_tools),
    }


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


def merge_decompiler_evidence(base_evidence: Mapping[str, Any], adversarial: Mapping[str, Any]) -> dict[str, Any]:
    """Attach a completed adversarial analyzer campaign to existing evidence."""
    merged = json.loads(json.dumps(base_evidence))
    passes = merged.get("passes")
    if not isinstance(passes, dict):
        raise ValueError("base maturity evidence is missing passes")
    for pass_name, evidence in passes.items():
        if not isinstance(pass_name, str) or not isinstance(evidence, dict):
            raise ValueError("base maturity evidence has an invalid pass row")
        evidence["decompiler"] = _decompiler_evidence(pass_name, adversarial)
    blockers = {
        field: sorted(
            pass_name
            for pass_name, evidence in passes.items()
            if isinstance(evidence.get(field), Mapping) and evidence[field].get("status") not in complete
        )
        for field, complete in (
            ("performance", {"complete"}),
            ("behavioral_false_positive", {"measured"}),
            ("affected_instructions", {"measured"}),
            ("composition", {"complete"}),
            ("decompiler", {"comparable"}),
        )
    }
    summary = merged.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("base maturity evidence is missing summary")
    summary["blockers"] = {field: values for field, values in blockers.items() if values}
    summary["blocker_totals"] = {field: len(values) for field, values in blockers.items()}
    summary["adversarial_evidence_attached"] = True
    return cast(dict[str, Any], merged)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--differential", type=Path, required=True)
    parser.add_argument("--extended", type=Path, required=True)
    parser.add_argument("--composition-dir", type=Path, required=True)
    parser.add_argument("--adversarial", type=Path)
    parser.add_argument("--base-evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    adversarial = _read_json(args.adversarial) if args.adversarial else None
    if args.base_evidence:
        if adversarial is None:
            raise ValueError("--base-evidence requires --adversarial")
        evidence = merge_decompiler_evidence(_read_json(args.base_evidence), adversarial)
    else:
        composition_paths = sorted(args.composition_dir.rglob("*.xml"))
        evidence = build_evidence(
            _read_json(args.differential),
            _read_json(args.extended),
            read_composition_evidence(composition_paths),
            adversarial,
        )
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
