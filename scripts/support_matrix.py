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
    maturity_summaries = _maturity_summary_counts(document.get("maturity"))
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
            "non_official_evidenced_cells": non_official_evidenced,
            "non_official_not_supported_cells": non_official_not_supported,
            "stability_counts": dict(sorted(stability_counts.items())),
            **{name: dict(sorted(counts.items())) for name, counts in maturity_summaries.items()},
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
