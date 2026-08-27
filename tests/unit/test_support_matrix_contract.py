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
