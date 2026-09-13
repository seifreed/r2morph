#!/usr/bin/env python3
"""Expand the declared pass support into an exhaustive matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

_MATURITY_STRING_FIELDS = (
    ("false_positive_risk", "false_positive_risk_counts"),
    ("decompiler_effectiveness", "decompiler_effectiveness_counts"),
    ("compatibility", "compatibility_counts"),
    ("performance", "performance_counts"),
    ("instructions_affected", "instructions_affected_counts"),
)
_MATURITY_SEQUENCE_FIELDS = (
    ("formats", "maturity_format_counts"),
    ("architectures", "maturity_architecture_counts"),
    ("unit_tests", "unit_test_evidence_counts"),
    ("e2e_tests", "e2e_test_evidence_counts"),
)
_MATURITY_GAP_VALUES = {
    "performance": {"Not measured per pass."},
    "false_positive_risk": {"Not independently measured."},
    "decompiler_effectiveness": {"Not independently measured."},
    "compatibility": {"Composition with other passes is not contractually supported."},
    "instructions_affected": {"Not exhaustively catalogued."},
}
_VM_SEMANTIC_GAP_SCOPE = (
    "memory",
    "direct-calls",
    "indirect-calls",
    "abi-varargs",
    "unwinding-exceptions",
    "tls-signals",
    "threads",
    "fp-simd",
    "ssa-liveness",
)
FULL_EVIDENCE_PERCENT = 100.0


def _add_count(counts: dict[str, int], value: str) -> None:
    counts[value] = counts.get(value, 0) + 1


def _merge_profile_counts(profile_fields: dict[str, Any], summaries: dict[str, dict[str, int]]) -> None:
    for field, summary_name in _MATURITY_STRING_FIELDS:
        value = profile_fields.get(field)
        if isinstance(value, str):
            _add_count(summaries[summary_name], value)
    for field, summary_name in _MATURITY_SEQUENCE_FIELDS:
        values = profile_fields.get(field)
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str):
                    _add_count(summaries[summary_name], value)


def _maturity_summary_counts(maturity: object) -> dict[str, dict[str, int]]:
    summaries = {
        "maturity_profile_counts": {},
        "false_positive_risk_counts": {},
        "decompiler_effectiveness_counts": {},
        "compatibility_counts": {},
        "performance_counts": {},
        "instructions_affected_counts": {},
        "maturity_format_counts": {},
        "maturity_architecture_counts": {},
        "unit_test_evidence_counts": {},
        "e2e_test_evidence_counts": {},
    }
    if not isinstance(maturity, dict):
        return summaries
    pass_profiles = maturity.get("pass_profiles")
    profiles = maturity.get("profiles")
    if not isinstance(pass_profiles, dict) or not isinstance(profiles, dict):
        return summaries
    for profile in pass_profiles.values():
        if not isinstance(profile, str):
            continue
        _add_count(summaries["maturity_profile_counts"], profile)
        profile_fields = profiles.get(profile)
        if isinstance(profile_fields, dict):
            _merge_profile_counts(profile_fields, summaries)
    return summaries


def _maturity_gap_passes(maturity: object) -> dict[str, list[str]]:
    gaps = {field: [] for field in _MATURITY_GAP_VALUES}
    if not isinstance(maturity, dict):
        return gaps
    pass_profiles = maturity.get("pass_profiles")
    profiles = maturity.get("profiles")
    if not isinstance(pass_profiles, dict) or not isinstance(profiles, dict):
        return gaps
    for pass_name, profile_name in pass_profiles.items():
        if not isinstance(pass_name, str) or not isinstance(profile_name, str):
            continue
        profile_fields = profiles.get(profile_name)
        if not isinstance(profile_fields, dict):
            continue
        for field, gap_values in _MATURITY_GAP_VALUES.items():
            if profile_fields.get(field) in gap_values:
                gaps[field].append(pass_name)
    return {field: sorted(pass_names) for field, pass_names in gaps.items()}


def _maturity_gaps_by_pass(maturity: object) -> dict[str, list[str]]:
    gaps: dict[str, list[str]] = {}
    if not isinstance(maturity, dict):
        return gaps
    pass_profiles = maturity.get("pass_profiles")
    profiles = maturity.get("profiles")
    if not isinstance(pass_profiles, dict) or not isinstance(profiles, dict):
        return gaps
    for pass_name, profile_name in pass_profiles.items():
        if not isinstance(pass_name, str) or not isinstance(profile_name, str):
            continue
        profile_fields = profiles.get(profile_name)
        if not isinstance(profile_fields, dict):
            continue
        fields = [
            field for field, gap_values in _MATURITY_GAP_VALUES.items() if profile_fields.get(field) in gap_values
        ]
        if fields:
            gaps[pass_name] = sorted(fields)
    return dict(sorted(gaps.items()))


def _maturity_evidence_blockers(
    maturity_gap_passes: dict[str, list[str]],
    maturity_gaps_by_pass: dict[str, list[str]],
) -> dict[str, object]:
    blockers: dict[str, object] = {}
    missing_fields = {field: pass_names for field, pass_names in maturity_gap_passes.items() if pass_names}
    if missing_fields:
        blockers["missing_fields_by_field"] = missing_fields
    if maturity_gaps_by_pass:
        blockers["missing_fields_by_pass"] = maturity_gaps_by_pass
    return blockers


def _coverage_percent(evidenced: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(evidenced / total * 100.0, 2)


def _non_official_gap_targets(
    cells: list[dict[str, Any]],
    official_format: object,
    official_architecture: object,
) -> list[dict[str, object]]:
    targets: dict[tuple[str, str], dict[str, object]] = {}
    for cell in cells:
        binary_format = cell["format"]
        architecture = cell["architecture"]
        if binary_format == official_format and architecture == official_architecture:
            continue
        key = (binary_format, architecture)
        target = targets.setdefault(
            key,
            {
                "format": binary_format,
                "architecture": architecture,
                "evidenced_cells": 0,
                "not_supported_cells": 0,
            },
        )
        field = "evidenced_cells" if cell["status"] == "evidenced" else "not_supported_cells"
        target[field] = int(target[field]) + 1
    rows = []
    for target in targets.values():
        total = int(target["evidenced_cells"]) + int(target["not_supported_cells"])
        target["evidence_percent"] = _coverage_percent(int(target["evidenced_cells"]), total)
        rows.append(target)
    return sorted(rows, key=lambda target: (str(target["format"]), str(target["architecture"])))


def _parity_gap_scope(
    formats: tuple[str, ...],
    architectures: tuple[str, ...],
    official_format: object,
    official_architecture: object,
) -> dict[str, list[str]]:
    return {
        "formats": sorted(binary_format for binary_format in formats if binary_format != official_format),
        "architectures": sorted(
            architecture for architecture in architectures if architecture != official_architecture
        ),
    }


def _parity_evidence_blockers(
    gap_targets: list[dict[str, object]],
    gap_scope: dict[str, list[str]],
) -> dict[str, object]:
    blockers: dict[str, object] = {}
    incomplete_targets = [
        target
        for target in gap_targets
        if isinstance(target.get("evidence_percent"), int | float)
        and target["evidence_percent"] < FULL_EVIDENCE_PERCENT
    ]
    if incomplete_targets:
        blockers["non_official_gap_targets"] = incomplete_targets
    if gap_scope["formats"] or gap_scope["architectures"]:
        blockers["parity_gap_scope"] = gap_scope
    return blockers


def build_matrix(document: dict[str, Any]) -> dict[str, Any]:
    """Build one explicit cell for every pass, format, and architecture."""
    formats = tuple(document.get("formats", {}))
    architectures = tuple(document.get("architectures", {}))
    official = document.get("official_target", {})
    official_format = official.get("format")
    official_architecture = official.get("architecture")
    cells: list[dict[str, Any]] = []
    stability_counts: dict[str, int] = {}
    for mutation_pass in document.get("passes", []):
        name = mutation_pass["name"]
        stability = mutation_pass.get("stability")
        if isinstance(stability, str):
            stability_counts[stability] = stability_counts.get(stability, 0) + 1
        supported_formats = set(mutation_pass.get("formats", []))
        supported_architectures = set(mutation_pass.get("architectures", []))
        evidence_cells = {(cell["format"], cell["architecture"]) for cell in mutation_pass.get("evidence_cells", [])}
        for binary_format in formats:
            for architecture in architectures:
                covered = (binary_format in supported_formats and architecture in supported_architectures) or (
                    binary_format,
                    architecture,
                ) in evidence_cells
                cells.append(
                    {
                        "pass": name,
                        "format": binary_format,
                        "architecture": architecture,
                        "status": "evidenced" if covered else "not-supported",
                        "evidence": mutation_pass.get("evidence", []) if covered else [],
                    }
                )
    evidenced = sum(1 for cell in cells if cell["status"] == "evidenced")
    official_evidenced = sum(
        1
        for cell in cells
        if cell["status"] == "evidenced"
        and cell["format"] == official_format
        and cell["architecture"] == official_architecture
    )
    official_not_supported = sum(
        1
        for cell in cells
        if cell["status"] == "not-supported"
        and cell["format"] == official_format
        and cell["architecture"] == official_architecture
    )
    non_official_evidenced = sum(
        1
        for cell in cells
        if cell["status"] == "evidenced"
        and (cell["format"] != official_format or cell["architecture"] != official_architecture)
    )
    non_official_not_supported = sum(
        1
        for cell in cells
        if cell["status"] == "not-supported"
        and (cell["format"] != official_format or cell["architecture"] != official_architecture)
    )
    official_cell_count = official_evidenced + official_not_supported
    non_official_cell_count = non_official_evidenced + non_official_not_supported
    maturity_summaries = _maturity_summary_counts(document.get("maturity"))
    maturity_gap_passes = _maturity_gap_passes(document.get("maturity"))
    maturity_gaps_by_pass = _maturity_gaps_by_pass(document.get("maturity"))
    non_official_gap_targets = _non_official_gap_targets(cells, official_format, official_architecture)
    parity_gap_scope = _parity_gap_scope(formats, architectures, official_format, official_architecture)
    return {
        "dimensions": {
            "passes": [mutation_pass["name"] for mutation_pass in document.get("passes", [])],
            "formats": list(formats),
            "architectures": list(architectures),
        },
        "cell_count": len(cells),
        "summary": {
            "evidenced_cells": evidenced,
            "not_supported_cells": len(cells) - evidenced,
            "official_evidenced_cells": official_evidenced,
            "official_not_supported_cells": official_not_supported,
            "official_evidence_percent": _coverage_percent(official_evidenced, official_cell_count),
            "non_official_evidenced_cells": non_official_evidenced,
            "non_official_not_supported_cells": non_official_not_supported,
            "non_official_evidence_percent": _coverage_percent(non_official_evidenced, non_official_cell_count),
            "non_official_gap_targets": non_official_gap_targets,
            "parity_gap_scope": parity_gap_scope,
            "parity_evidence_blockers": _parity_evidence_blockers(
                non_official_gap_targets,
                parity_gap_scope,
            ),
            "stability_counts": dict(sorted(stability_counts.items())),
            **{name: dict(sorted(counts.items())) for name, counts in maturity_summaries.items()},
            "maturity_gap_passes": maturity_gap_passes,
            "maturity_gaps_by_pass": maturity_gaps_by_pass,
            "maturity_evidence_blockers": _maturity_evidence_blockers(
                maturity_gap_passes,
                maturity_gaps_by_pass,
            ),
            "vm_semantic_gap_scope": list(_VM_SEMANTIC_GAP_SCOPE),
        },
        "cells": cells,
    }


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("support matrix must contain a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("matrix", type=Path, default=Path("docs/support-matrix.json"), nargs="?")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write and args.check:
        parser.error("--write and --check are mutually exclusive")
    document = _load(args.matrix)
    expected = build_matrix(document)
    if args.check:
        if document.get("matrix") != expected:
            raise SystemExit("support matrix is missing an up-to-date exhaustive matrix")
    elif args.write:
        document["matrix"] = expected
        args.matrix.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    else:
        print(json.dumps(expected, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
