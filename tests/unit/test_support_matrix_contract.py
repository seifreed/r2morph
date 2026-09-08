"""Regression contract for exhaustive pass support cells."""

import json
from pathlib import Path

from scripts.support_matrix import build_matrix
from tests.utils.assertions import expect

_MATRIX = Path(__file__).resolve().parents[2] / "docs" / "support-matrix.json"


def test_support_matrix_has_one_cell_per_declared_combination() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    matrix = build_matrix(document)
    dimensions = matrix["dimensions"]

    expected_count = len(dimensions["passes"]) * len(dimensions["formats"]) * len(dimensions["architectures"])
    expect(matrix["cell_count"] == expected_count and len(matrix["cells"]) == expected_count)


def test_support_matrix_marks_unsupported_combinations_without_evidence() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    matrix = build_matrix(document)
    unsupported = [cell for cell in matrix["cells"] if cell["status"] == "not-supported"]

    expect(unsupported and all(cell["evidence"] == [] for cell in unsupported))


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
