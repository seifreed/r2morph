"""Regression contract for exhaustive pass support cells."""

import json
from pathlib import Path

from scripts.support_matrix import build_matrix
from tests.utils.assertions import expect

_MATRIX = Path(__file__).resolve().parents[2] / "docs" / "support-matrix.json"
_EXPECTED_EVIDENCED_CELLS = 29
_EXPECTED_NOT_SUPPORTED_CELLS = 235
_EXPECTED_NON_OFFICIAL_EVIDENCED_CELLS = 7
_EXPECTED_NON_OFFICIAL_NOT_SUPPORTED_CELLS = 235
_EXPECTED_STABILITY_COUNTS = {"experimental": 19, "tier-1": 3}
_EXPECTED_MATURITY_PROFILE_COUNTS = {
    "code-virtualization": 1,
    "experimental": 12,
    "experimental-corpus-selected": 6,
    "tier-1-native": 3,
}


def test_support_matrix_has_one_cell_per_declared_combination() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    matrix = build_matrix(document)
    dimensions = matrix["dimensions"]

    expected_count = len(dimensions["passes"]) * len(dimensions["formats"]) * len(dimensions["architectures"])
    expect(matrix["cell_count"] == expected_count and len(matrix["cells"]) == expected_count)


def test_support_matrix_report_matches_current_declarations() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))

    expect(document["matrix"] == build_matrix(document))


def test_support_matrix_marks_unsupported_combinations_without_evidence() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    matrix = build_matrix(document)
    unsupported = [cell for cell in matrix["cells"] if cell["status"] == "not-supported"]

    expect(unsupported and all(cell["evidence"] == [] for cell in unsupported))


def test_support_matrix_summarizes_parity_gaps() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    summary = build_matrix(document)["summary"]

    expect(
        summary["evidenced_cells"] == _EXPECTED_EVIDENCED_CELLS
        and summary["not_supported_cells"] == _EXPECTED_NOT_SUPPORTED_CELLS
        and summary["non_official_evidenced_cells"] == _EXPECTED_NON_OFFICIAL_EVIDENCED_CELLS
        and summary["non_official_not_supported_cells"] == _EXPECTED_NON_OFFICIAL_NOT_SUPPORTED_CELLS
        and summary["stability_counts"] == _EXPECTED_STABILITY_COUNTS
        and summary["maturity_profile_counts"] == _EXPECTED_MATURITY_PROFILE_COUNTS
    )


def test_support_matrix_declares_virtualization_static_dataflow_gate() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    profile_name = document["maturity"]["pass_profiles"]["code-virtualization"]
    preconditions = document["maturity"]["profiles"][profile_name]["preconditions"]

    expect(all(term in preconditions for term in ("CFG", "SSA", "liveness")))


def test_support_matrix_declares_virtualization_runtime_boundary_coverage() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    profile_name = document["maturity"]["pass_profiles"]["code-virtualization"]
    instructions = document["maturity"]["profiles"][profile_name]["instructions_affected"]

    expect(all(term in instructions for term in ("stack/ABI", "TLS", "signals", "threads")))


def test_support_matrix_honors_explicit_evidence_cells() -> None:
    document = {
        "formats": {"PE": "preview"},
        "architectures": {"AArch64": "experimental"},
        "passes": [
            {
                "name": "nop",
                "formats": [],
                "architectures": [],
                "evidence_cells": [{"format": "PE", "architecture": "AArch64"}],
                "evidence": ["tests/integration"],
            }
        ],
    }

    expect(build_matrix(document)["cells"][0]["status"] == "evidenced")


def test_support_matrix_keeps_non_official_targets_out_of_supported_status() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    cells = build_matrix(document)["cells"]
    non_official_cells = [cell for cell in cells if cell["format"] != "ELF" or cell["architecture"] != "x86-64"]

    expect(non_official_cells and all(cell["status"] != "supported" for cell in non_official_cells))
