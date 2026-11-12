"""Regression contract for exhaustive pass support cells."""

import ast
import json
from pathlib import Path

from scripts.support_matrix import build_matrix
from tests.utils.assertions import expect

_README = Path(__file__).resolve().parents[2] / "README.md"
_PASS_MATURITY = Path(__file__).resolve().parents[2] / "docs" / "pass-maturity.md"
_MATRIX = Path(__file__).resolve().parents[2] / "docs" / "support-matrix.json"
_EXPECTED_EVIDENCED_CELLS = 62
_EXPECTED_NOT_SUPPORTED_CELLS = 202
_EXPECTED_DECLARED_SUPPORT_CELLS = 62
_EXPECTED_UNCLAIMED_CELLS = 202
_EXPECTED_TARGET_SUPPORT_STATUS_COUNTS = {"experimental": 45, "preview": 12, "supported": 5}
_EXPECTED_NON_OFFICIAL_EVIDENCED_CELLS = 40
_EXPECTED_NON_OFFICIAL_NOT_SUPPORTED_CELLS = 202
_EXPECTED_NON_OFFICIAL_MISSING_EVIDENCE_CELLS = 202
_EXPECTED_STABILITY_COUNTS = {"experimental": 17, "tier-1": 5}
_EXPECTED_MATURITY_PROFILE_COUNTS = {
    "anti-disassembly-instruction-catalogued": 1,
    "api-hashing-instruction-catalogued": 1,
    "code-mobility-instruction-catalogued": 1,
    "code-virtualization": 1,
    "data-flow-mutation-instruction-catalogued": 1,
    "experimental-corpus-selected": 4,
    "function-outlining-instruction-catalogued": 1,
    "import-obfuscation-instruction-catalogued": 1,
    "opaque-predicates-instruction-catalogued": 1,
    "polymorphic-engine-instruction-catalogued": 1,
    "self-modifying-code-instruction-catalogued": 1,
    "short-jump-patching-instruction-catalogued": 1,
    "stack-strings-instruction-catalogued": 1,
    "string-obfuscation-instruction-catalogued": 1,
    "tier-1-native": 5,
}
_EXPECTED_MATURITY_GAP_CATEGORIES = 0
_EXPECTED_TOTAL_MATURITY_FIELD_GAPS = 0
_EXPECTED_TOTAL_MATURITY_BLOCKERS = 0


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


def test_support_matrix_records_pe_x86_nop_evidence_as_preview() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    matrix = build_matrix(document)
    cell = next(
        cell for cell in matrix["cells"] if (cell["pass"], cell["format"], cell["architecture"]) == ("nop", "PE", "x86")
    )

    expect(
        cell["status"] == "evidenced"
        and cell["support_status"] == "preview"
        and cell["evidence"]
        == ["tests/integration/test_nop_insertion_pe_real.py::test_nop_insertion_pe_x86_preserves_native_execution"]
    )


def test_support_matrix_records_pe_x86_tier1_mutation_evidence() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    cells = {
        cell["pass"]: cell
        for cell in build_matrix(document)["cells"]
        if cell["format"] == "PE" and cell["architecture"] == "x86"
    }
    expected_passes = {"nop", "substitute", "register", "instruction-expansion"}

    expect(
        all(
            cells[pass_name]["status"] == "evidenced" and cells[pass_name]["support_status"] == "preview"
            for pass_name in expected_passes
        )
    )


def test_support_matrix_summarizes_parity_gaps() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    summary = build_matrix(document)["summary"]
    parity_totals = summary["parity_blocker_totals"]

    expect(
        summary["evidenced_cells"] == _EXPECTED_EVIDENCED_CELLS
        and summary["not_supported_cells"] == _EXPECTED_NOT_SUPPORTED_CELLS
        and summary["declared_support_cells"] == _EXPECTED_DECLARED_SUPPORT_CELLS
        and summary["unclaimed_cells"] == _EXPECTED_UNCLAIMED_CELLS
        and summary["target_support_status_counts"] == _EXPECTED_TARGET_SUPPORT_STATUS_COUNTS
        and summary["non_official_evidenced_cells"] == _EXPECTED_NON_OFFICIAL_EVIDENCED_CELLS
        and summary["non_official_not_supported_cells"] == _EXPECTED_NON_OFFICIAL_NOT_SUPPORTED_CELLS
        and parity_totals["non_official_missing_evidence_cells"] == _EXPECTED_NON_OFFICIAL_MISSING_EVIDENCE_CELLS
        and summary["stability_counts"] == _EXPECTED_STABILITY_COUNTS
        and summary["maturity_profile_counts"] == _EXPECTED_MATURITY_PROFILE_COUNTS
    )


def test_support_matrix_summarizes_total_maturity_field_gaps() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    totals = build_matrix(document)["summary"]["maturity_blocker_totals"]

    expect(
        totals["maturity_gap_categories"] == _EXPECTED_MATURITY_GAP_CATEGORIES
        and totals["total_maturity_field_gaps"] == _EXPECTED_TOTAL_MATURITY_FIELD_GAPS
        and totals["total_maturity_blockers"] == _EXPECTED_TOTAL_MATURITY_BLOCKERS
    )


def test_support_matrix_readme_parity_gap_matches_generated_summary() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    summary = build_matrix(document)["summary"]
    official_total = summary["official_evidenced_cells"] + summary["official_not_supported_cells"]
    non_official_total = summary["non_official_evidenced_cells"] + summary["non_official_not_supported_cells"]
    readme = _README.read_text(encoding="utf-8")

    expect(
        f"{summary['official_evidenced_cells']}/{official_total} evidenced cells for the official" in readme
        and f"{summary['non_official_evidenced_cells']}/{non_official_total} evidenced cells for non-official" in readme
    )


def test_readme_key_features_names_every_tier_1_pass() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    tier_1_passes = [entry["name"] for entry in document["passes"] if entry["stability"] == "tier-1"]
    readme = _README.read_text(encoding="utf-8")

    expect(
        tier_1_passes == ["nop", "substitute", "register", "instruction-expansion", "block-reordering"]
        and (
            "NOP, instruction substitution, register substitution, instruction expansion, and block reordering "
            "on the official target"
        )
        in readme
    )


def test_pass_maturity_keeps_preview_targets_out_of_parity_claims() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    summary = build_matrix(document)["summary"]
    contract = " ".join(_PASS_MATURITY.read_text(encoding="utf-8").split())

    expect(
        "Preview PE, Mach-O, ARM, and AArch64 evidence does not imply parity" in contract
        and "`target_cells` is the canonical support contract" in contract
        and "must not be cross-multiplied" in contract
        and "preview coverage cannot look equivalent to the supported baseline" in contract
        and str(summary["non_official_evidenced_cells"]) in contract
        and str(summary["non_official_not_supported_cells"]) in contract
    )


def test_support_matrix_declares_virtualization_static_dataflow_gate() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    profile_name = document["maturity"]["pass_profiles"]["code-virtualization"]
    preconditions = document["maturity"]["profiles"][profile_name]["preconditions"]

    expect(
        all(term in preconditions for term in ("Whole-function semantics", "CFG", "SSA", "liveness"))
        and "unsupported capabilities are rejected before mutation" in preconditions
    )


def test_support_matrix_declares_virtualization_runtime_boundary_coverage() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    profile_name = document["maturity"]["pass_profiles"]["code-virtualization"]
    instructions = document["maturity"]["profiles"][profile_name]["instructions_affected"]

    expect(
        all(
            term in instructions
            for term in (
                "memory",
                "calls/returns",
                "stack/ABI",
                "TLS",
                "signals",
                "threads",
                "floating-point",
                "SIMD",
                "exception/unwinding",
                "diagnostics",
            )
        )
    )


def test_support_matrix_limits_code_virtualization_to_official_target() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    entry = next(item for item in document["passes"] if item["name"] == "code-virtualization")
    cells = [cell for cell in build_matrix(document)["cells"] if cell.get("pass") == "code-virtualization"]
    official = [cell for cell in cells if cell["format"] == "ELF" and cell["architecture"] == "x86-64"]
    non_official = [cell for cell in cells if cell not in official]

    expect(
        entry["formats"] == ["ELF"]
        and entry["architectures"] == ["x86-64"]
        and len(official) == 1
        and official[0]["status"] == "evidenced"
        and all(cell["status"] == "not-supported" and cell["evidence"] == [] for cell in non_official)
    )


def test_support_matrix_honors_explicit_evidence_cells() -> None:
    document = {
        "formats": {"PE": "preview"},
        "architectures": {"AArch64": "experimental"},
        "passes": [
            {
                "name": "nop",
                "formats": ["PE"],
                "architectures": ["AArch64"],
                "target_cells": [{"format": "PE", "architecture": "AArch64", "support_status": "experimental"}],
                "evidence_cells": [
                    {
                        "format": "PE",
                        "architecture": "AArch64",
                        "evidence": ["tests/integration/test_pe_aarch64.py::test_real_execution"],
                    }
                ],
                "evidence": ["tests/integration"],
            }
        ],
    }

    expect(build_matrix(document)["cells"][0]["status"] == "evidenced")


def test_support_matrix_does_not_expand_target_cells_cartesianly() -> None:
    document = {
        "formats": {"ELF": "official", "PE": "preview"},
        "architectures": {"x86-64": "official", "AArch64": "experimental"},
        "official_target": {"format": "ELF", "architecture": "x86-64"},
        "passes": [
            {
                "name": "nop",
                "stability": "tier-1",
                "formats": ["ELF", "PE"],
                "architectures": ["x86-64", "AArch64"],
                "target_cells": [
                    {"format": "ELF", "architecture": "x86-64", "support_status": "supported"},
                    {"format": "PE", "architecture": "x86-64", "support_status": "preview"},
                    {"format": "ELF", "architecture": "AArch64", "support_status": "experimental"},
                ],
                "evidence_cells": [
                    {
                        "format": "ELF",
                        "architecture": "x86-64",
                        "evidence": ["tests/integration/test_elf_nop.py::test_nop"],
                    },
                    {
                        "format": "PE",
                        "architecture": "x86-64",
                        "evidence": ["tests/integration/test_pe_nop.py::test_nop"],
                    },
                    {
                        "format": "ELF",
                        "architecture": "AArch64",
                        "evidence": ["tests/integration/test_arm64_nop.py::test_nop"],
                    },
                ],
                "evidence": ["tests/integration"],
            }
        ],
    }

    cells = build_matrix(document)["cells"]
    pe_aarch64 = next(cell for cell in cells if cell["format"] == "PE" and cell["architecture"] == "AArch64")

    expect(
        not pe_aarch64["declared_support"]
        and pe_aarch64["support_status"] is None
        and pe_aarch64["status"] == "not-supported"
    )


def test_support_matrix_uses_target_specific_evidence_without_inheriting_other_targets() -> None:
    document = {
        "formats": {"ELF": "official", "PE": "preview"},
        "architectures": {"x86-64": "official"},
        "official_target": {"format": "ELF", "architecture": "x86-64"},
        "passes": [
            {
                "name": "nop",
                "stability": "tier-1",
                "formats": ["ELF", "PE"],
                "architectures": ["x86-64"],
                "target_cells": [
                    {"format": "ELF", "architecture": "x86-64", "support_status": "supported"},
                    {"format": "PE", "architecture": "x86-64", "support_status": "preview"},
                ],
                "evidence": ["tests/integration/test_linux_nop.py::test_linux_execution"],
                "evidence_cells": [
                    {
                        "format": "PE",
                        "architecture": "x86-64",
                        "evidence": ["tests/integration/test_pe_nop.py::test_pe_execution"],
                    }
                ],
            }
        ],
    }

    pe_cell = next(cell for cell in build_matrix(document)["cells"] if cell["format"] == "PE")

    expect(pe_cell["evidence"] == ["tests/integration/test_pe_nop.py::test_pe_execution"])


def test_support_matrix_preview_evidence_references_real_test_cases() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    preview_cells = [
        cell
        for cell in document["matrix"]["cells"]
        if cell["status"] == "evidenced" and (cell["format"] != "ELF" or cell["architecture"] != "x86-64")
    ]
    missing_cases = []
    for cell in preview_cells:
        for reference in cell["evidence"]:
            path_text, case_name = reference.split("::", maxsplit=1)
            definition_name = case_name.split("[", maxsplit=1)[0]
            source = (_MATRIX.parents[1] / path_text).read_text(encoding="utf-8")
            definitions = {
                node.name
                for node in ast.walk(ast.parse(source))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            if definition_name not in definitions:
                missing_cases.append(reference)

    expect(not missing_cases)


def test_support_matrix_does_not_turn_declared_support_into_evidence() -> None:
    document = {
        "formats": {"ELF": "official"},
        "architectures": {"x86-64": "official"},
        "official_target": {"format": "ELF", "architecture": "x86-64"},
        "passes": [
            {
                "name": "nop",
                "stability": "tier-1",
                "formats": ["ELF"],
                "architectures": ["x86-64"],
                "target_cells": [{"format": "ELF", "architecture": "x86-64", "support_status": "supported"}],
                "evidence_cells": [],
                "evidence": ["tests/integration"],
            }
        ],
    }

    cell = build_matrix(document)["cells"][0]

    expect(cell["declared_support"] and cell["status"] == "not-supported" and cell["evidence"] == [])


def test_support_matrix_keeps_non_official_targets_out_of_supported_status() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    cells = build_matrix(document)["cells"]
    non_official_cells = [cell for cell in cells if cell["format"] != "ELF" or cell["architecture"] != "x86-64"]

    expect(non_official_cells and all(cell["support_status"] != "supported" for cell in non_official_cells))


def test_support_matrix_records_preview_cells_backed_by_native_smoke() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    cells_by_pass = {entry["name"]: entry["evidence_cells"] for entry in document["passes"]}

    expect(
        all(
            any(
                evidence_cell["format"] == cell["format"] and evidence_cell["architecture"] == cell["architecture"]
                for evidence_cell in cells_by_pass[pass_name]
            )
            for pass_name, cell in (
                ("nop", {"format": "PE", "architecture": "x86-64"}),
                ("block-reordering", {"format": "PE", "architecture": "x86-64"}),
                ("substitute", {"format": "Mach-O", "architecture": "x86-64"}),
                ("register", {"format": "Mach-O", "architecture": "x86-64"}),
                ("instruction-expansion", {"format": "Mach-O", "architecture": "x86-64"}),
            )
        )
    )


def test_support_matrix_records_macho_block_reordering_as_one_preview_case() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    entry = next(item for item in document["passes"] if item["name"] == "block-reordering")
    cell = next(
        cell
        for cell in build_matrix(document)["cells"]
        if cell["pass"] == entry["name"] and cell["format"] == "Mach-O" and cell["architecture"] == "x86-64"
    )

    expect(
        entry["stability"] == "tier-1"
        and "Mach-O" in entry["formats"]
        and cell["support_status"] == "experimental"
        and cell["status"] == "evidenced"
        and cell["evidence"]
        == [
            "tests/integration/test_mutations_x86_compiled_binary.py::"
            "test_x86_block_reordering_preserves_native_exit_code"
        ]
    )


def test_support_matrix_records_pe_block_reordering_as_preview_evidence() -> None:
    document = json.loads(_MATRIX.read_text(encoding="utf-8"))
    entry = next(item for item in document["passes"] if item["name"] == "block-reordering")
    cell = next(
        cell
        for cell in build_matrix(document)["cells"]
        if cell["pass"] == entry["name"] and cell["format"] == "PE" and cell["architecture"] == "x86-64"
    )

    expect(
        entry["stability"] == "tier-1"
        and cell["support_status"] == "preview"
        and cell["status"] == "evidenced"
        and cell["evidence"]
        == [
            "tests/integration/test_block_reordering_pe_real.py::test_pe_x86_64_block_reordering_preserves_native_observables"
        ]
    )
