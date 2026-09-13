"""Regression tests for the versioned support contract."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.check_release_contract import (
    _check_changelog,
    _check_corpus_pass_selection_docs,
    _check_corpus_workflows,
    _check_documentation_claims,
    _check_documentation_links,
    _check_independent_review_artifact,
    _check_independent_review_packet_claims,
    _check_matrix,
    _check_pass_maturity_gap_summary,
    _check_pass_selection_contract,
    _check_readme_adversarial_summary,
    _check_readme_cross_platform_parity,
    _check_readme_differential_summary,
    _check_readme_pass_surface,
    _check_readme_support_summary,
    _check_readme_vm_resistance_summary,
    _check_readme_vm_review_scope,
    _check_release_blockers,
    _forbidden_release_claims,
    _validate_adversarial_benchmark_artifact,
    _validate_independent_review_artifact,
    _validate_independent_review_freshness,
    _validate_inventory,
    _validate_release_blockers_text,
    _validate_vm_resistance_artifacts,
    main,
)
from scripts.support_matrix import build_matrix
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MIN_CONCRETE_PASSES = 20
_FULL_COVERAGE_PERCENT = 100.0
_CORPUS_SELECTED_EXPERIMENTAL_PASSES = {
    "instruction-expansion",
    "block-reordering",
    "dead-code-injection",
    "control-flow-flattening",
    "constant-unfolding",
    "pattern-substitution",
}


def test_support_matrix_declares_linux_elf_x86_64_as_official() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))

    expect(
        matrix["official_target"] == {"os": "linux", "format": "ELF", "architecture": "x86-64", "status": "supported"}
    )


def test_support_matrix_keeps_preview_targets_out_of_official_support() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))

    expect(
        matrix["formats"]
        == {
            "ELF": "official-linux-x86-64",
            "PE": "preview-alpha",
            "Mach-O": "experimental",
        }
        and matrix["architectures"]
        == {
            "x86-64": "official-linux-elf",
            "x86": "experimental",
            "AArch64": "experimental",
            "ARM": "experimental",
        }
    )


def test_support_matrix_evidence_paths_exist() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    paths = [
        evidence for entry in matrix["passes"] for evidence in entry["evidence"] if not evidence.startswith("http")
    ]

    expect(all((_ROOT / evidence).exists() for evidence in paths), f"missing evidence: {paths}")


def test_support_matrix_enumerates_concrete_unique_passes() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    names = [entry["name"] for entry in matrix["passes"]]

    expect(
        len(names) == len(set(names)) and "experimental-passes" not in names and len(names) >= _MIN_CONCRETE_PASSES,
        "support matrix must enumerate concrete passes without duplicates",
    )


def test_support_matrix_partitions_cli_and_engine_only_passes() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    pass_names = {entry["name"] for entry in matrix["passes"]}

    expect(_check_pass_selection_contract(matrix, pass_names) is None)


def test_support_matrix_declares_maturity_profile_for_each_pass() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    pass_names = {entry["name"] for entry in matrix["passes"]}
    maturity = matrix["maturity"]

    expect(
        set(maturity["pass_profiles"]) == pass_names
        and all(
            set(maturity["profiles"][profile]) == set(maturity["required_fields"])
            for profile in set(maturity["pass_profiles"].values())
        )
    )


def test_pass_maturity_contract_names_the_public_corpus_selection() -> None:
    contract = (_ROOT / "docs" / "pass-maturity.md").read_text(encoding="utf-8")

    expect(_check_corpus_pass_selection_docs() is None)
    expect("broad corpus evidence is pending" not in contract)


def test_compatibility_corpus_names_the_full_pass_selection() -> None:
    expect(_check_corpus_pass_selection_docs() is None)


def test_compatibility_corpus_documents_differential_metrics() -> None:
    contract = " ".join((_ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8").split())

    expect(
        "Each transformed image must preserve the native result" in contract
        and "stdout and stderr" in contract
        and "output size/hash" in contract
        and "transform-duration, runtime-duration, and static analyzer evidence" in contract
        and "runtime-observable failure reasons" in contract
    )


def test_compatibility_corpus_does_not_promote_historical_six_pass_campaign() -> None:
    contract = " ".join((_ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8").split())

    expect(
        "six selected passes available at that commit" in contract
        and "a full ten-pass campaign is required before this document claims a complete Linux CI record" in contract
    )


def test_local_adversarial_angr_evidence_completes_original_and_protected() -> None:
    report = json.loads(
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-13-13214f9.json").read_text(encoding="utf-8")
    )
    tools = {row["tool"]: row for row in report["tools"]}
    angr = tools["angr"]

    expect(
        report["original"] == "elf_vm_fppackedidxnb_x86_64"
        and report["passes"][0]["status"] == "applied"
        and report["passes"][0]["unsupported_functions"] == 0
        and report["passes"][0]["partial_virtualization"] == 0
        and angr["status"] == "completed"
        and angr["original"]["status"] == "completed"
        and angr["protected"]["status"] == "completed"
    )


def test_release_contract_rejects_missing_binary_ninja_slot() -> None:
    report = json.loads(
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-13-13214f9.json").read_text(encoding="utf-8")
    )
    report["tools"] = [row for row in report["tools"] if row["tool"] != "binary-ninja"]

    rejected = False
    try:
        _validate_adversarial_benchmark_artifact(report)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_incomplete_completed_analyzer_row() -> None:
    report = json.loads(
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-13-13214f9.json").read_text(encoding="utf-8")
    )
    tools = {row["tool"]: row for row in report["tools"]}
    del tools["angr"]["protected"]

    rejected = False
    try:
        _validate_adversarial_benchmark_artifact(report)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_unexplained_unavailable_analyzer_row() -> None:
    report = json.loads(
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-13-13214f9.json").read_text(encoding="utf-8")
    )
    tools = {row["tool"]: row for row in report["tools"]}
    tools["binary-ninja"]["reason"] = ""

    rejected = False
    try:
        _validate_adversarial_benchmark_artifact(report)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_adversarial_benchmark_without_signoff_blockers() -> None:
    report = json.loads(
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-13-13214f9.json").read_text(encoding="utf-8")
    )
    del report["release_signoff_blockers"]

    rejected = False
    try:
        _validate_adversarial_benchmark_artifact(report)
    except ValueError:
        rejected = True

    expect(rejected)


def test_compatibility_corpus_documents_closed_virtualization_diagnostics() -> None:
    contract = " ".join((_ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8").split())

    expect(
        "Unsupported-virtualization diagnostics identify the function address, instruction address, "
        "missing capability, reason, and severity" in contract
        and "Partial-virtualization diagnostics are rendered with the same bounded capability" in contract
        and "partial-only virtualization result is classified as an omitted pass with its diagnostic reason" in contract
        and "Each unsupported-function diagnostic keeps the rejected instruction address, mnemonic, type, size"
        in contract
    )


def test_support_matrix_uses_corpus_selected_profile_for_measured_experimental_passes() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    maturity = matrix["maturity"]

    expect(
        all(
            maturity["pass_profiles"][pass_name] == "experimental-corpus-selected"
            for pass_name in _CORPUS_SELECTED_EXPERIMENTAL_PASSES
        )
        and "output-size" in maturity["profiles"]["experimental-corpus-selected"]["performance"]
        and "adversarial benchmark" in maturity["profiles"]["experimental-corpus-selected"]["decompiler_effectiveness"]
    )


def test_support_matrix_summarizes_false_positive_risk_profiles() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        sum(summary["false_positive_risk_counts"].values()) == len(matrix["passes"])
        and any("Not independently measured" in risk for risk in summary["false_positive_risk_counts"])
    )


def test_support_matrix_summarizes_decompiler_effectiveness_profiles() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        sum(summary["decompiler_effectiveness_counts"].values()) == len(matrix["passes"])
        and any("Not independently measured" in value for value in summary["decompiler_effectiveness_counts"])
    )


def test_support_matrix_summarizes_compatibility_profiles() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        sum(summary["compatibility_counts"].values()) == len(matrix["passes"])
        and any("not exhaustively covered" in value for value in summary["compatibility_counts"])
    )


def test_support_matrix_summarizes_performance_profiles() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        sum(summary["performance_counts"].values()) == len(matrix["passes"])
        and any("Not measured" in value for value in summary["performance_counts"])
    )


def test_support_matrix_summarizes_instruction_coverage_profiles() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        sum(summary["instructions_affected_counts"].values()) == len(matrix["passes"])
        and any("Not exhaustively catalogued" in value for value in summary["instructions_affected_counts"])
    )


def test_support_matrix_names_maturity_gap_passes() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    gaps = summary["maturity_gap_passes"]

    expect(
        set(gaps)
        == {
            "performance",
            "false_positive_risk",
            "decompiler_effectiveness",
            "compatibility",
            "instructions_affected",
        }
        and len(gaps["performance"]) == summary["performance_counts"]["Not measured per pass."]
        and len(gaps["false_positive_risk"]) == summary["false_positive_risk_counts"]["Not independently measured."]
        and len(gaps["decompiler_effectiveness"])
        == summary["decompiler_effectiveness_counts"]["Not independently measured."]
        and len(gaps["compatibility"])
        == summary["compatibility_counts"]["Composition with other passes is not contractually supported."]
        and len(gaps["instructions_affected"])
        == summary["instructions_affected_counts"]["Not exhaustively catalogued."]
    )


def test_support_matrix_names_maturity_gaps_by_pass() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    gaps_by_field = summary["maturity_gap_passes"]
    gaps_by_pass = summary["maturity_gaps_by_pass"]
    inverted = {
        field: sorted(pass_name for pass_name, fields in gaps_by_pass.items() if field in fields)
        for field in gaps_by_field
    }

    expect(
        inverted == gaps_by_field
        and "anti-disassembly" in gaps_by_pass
        and "performance" in gaps_by_pass["anti-disassembly"]
        and all(gaps for gaps in gaps_by_pass.values())
    )


def test_support_matrix_names_maturity_evidence_blockers() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    blockers = summary["maturity_evidence_blockers"]

    expect(
        blockers["native_evidence_gap_passes"] == summary["native_evidence_gap_passes"]
        and blockers["missing_fields_by_field"] == summary["maturity_gap_passes"]
        and blockers["missing_fields_by_pass"] == summary["maturity_gaps_by_pass"]
        and "performance" in blockers["missing_fields_by_field"]
        and "anti-disassembly" in blockers["missing_fields_by_pass"]
    )


def test_support_matrix_counts_maturity_blockers() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    totals = summary["maturity_blocker_totals"]

    expect(
        totals["native_evidence_gap_passes"] == len(summary["native_evidence_gap_passes"])
        and totals["passes_with_maturity_field_gaps"] == len(summary["maturity_gaps_by_pass"])
        and all(
            totals[f"{field}_gap_passes"] == len(pass_names)
            for field, pass_names in summary["maturity_gap_passes"].items()
        )
    )


def test_support_matrix_names_vm_semantic_gap_scope() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        summary["vm_semantic_gap_scope"]
        == [
            "memory",
            "direct-calls",
            "indirect-calls",
            "abi-varargs",
            "unwinding-exceptions",
            "tls-signals",
            "threads",
            "fp-simd",
            "ssa-liveness",
        ]
    )


def test_support_matrix_names_vm_resistance_gap_scope() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        summary["vm_resistance_gap_scope"]
        == [
            "human-adversarial-validation",
            "isa-opcode-diversity",
            "handler-diversity",
            "dispatcher-diversity",
            "anti-tamper",
            "progressive-bytecode-protection",
        ]
    )


def test_support_matrix_summarizes_maturity_target_profiles() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        summary["maturity_format_counts"] == {"ELF": len(matrix["passes"])}
        and summary["maturity_architecture_counts"] == {"x86-64": len(matrix["passes"])}
    )


def test_support_matrix_summarizes_official_target_cells() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        summary["official_evidenced_cells"] + summary["official_not_supported_cells"] == len(matrix["passes"])
        and summary["official_evidenced_cells"] == len(matrix["passes"])
        and summary["official_evidence_percent"] == _FULL_COVERAGE_PERCENT
        and summary["non_official_evidence_percent"] < summary["official_evidence_percent"]
    )


def test_support_matrix_names_non_official_parity_gaps() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    official = matrix["official_target"]
    gap_targets = summary["non_official_gap_targets"]
    expected_targets = {
        (binary_format, architecture)
        for binary_format in matrix["formats"]
        for architecture in matrix["architectures"]
        if (binary_format, architecture) != (official["format"], official["architecture"])
    }

    expect(
        {(row["format"], row["architecture"]) for row in gap_targets} == expected_targets
        and sum(row["evidenced_cells"] for row in gap_targets) == summary["non_official_evidenced_cells"]
        and sum(row["not_supported_cells"] for row in gap_targets) == summary["non_official_not_supported_cells"]
        and all(row["evidence_percent"] < summary["official_evidence_percent"] for row in gap_targets)
    )


def test_support_matrix_names_parity_gap_scope() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        summary["parity_gap_scope"]
        == {
            "formats": ["Mach-O", "PE"],
            "architectures": ["AArch64", "ARM", "x86"],
        }
    )


def test_support_matrix_names_parity_evidence_blockers() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    blockers = summary["parity_evidence_blockers"]

    expect(
        blockers["parity_gap_scope"] == summary["parity_gap_scope"]
        and blockers["non_official_gap_targets"] == summary["non_official_gap_targets"]
        and all(
            target["evidence_percent"] < summary["official_evidence_percent"]
            for target in blockers["non_official_gap_targets"]
        )
    )


def test_release_contract_rejects_non_official_parity_claim() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["non_official_evidence_percent"] = matrix["matrix"]["summary"][
        "official_evidence_percent"
    ]

    rejected = False
    try:
        _check_matrix(matrix, matrix["release"])
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_stale_generated_support_matrix() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["cell_count"] += 1

    rejected = False
    try:
        _check_matrix(matrix, matrix["release"])
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_tier_1_profile_drift() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["maturity"]["pass_profiles"]["nop"] = "experimental"
    matrix["matrix"] = build_matrix(matrix)

    rejected = False
    try:
        _check_matrix(matrix, matrix["release"])
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_empty_maturity_profile_field() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["maturity"]["profiles"]["experimental"]["performance"] = ""
    matrix["matrix"] = build_matrix(matrix)

    rejected = False
    try:
        _check_matrix(matrix, matrix["release"])
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_missing_maturity_evidence_path() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["maturity"]["profiles"]["experimental"]["unit_tests"] = ["tests/missing-unit-evidence"]
    matrix["matrix"] = build_matrix(matrix)

    rejected = False
    try:
        _check_matrix(matrix, matrix["release"])
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_stale_readme_support_summary() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["non_official_evidenced_cells"] += 1

    rejected = False
    try:
        _check_readme_support_summary(matrix)
    except ValueError:
        rejected = True

    expect(rejected)


def test_readme_support_claims_match_release_artifacts() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))

    expect(
        _check_readme_support_summary(matrix) is None
        and _check_readme_pass_surface(matrix) is None
        and _check_readme_cross_platform_parity() is None
        and _check_readme_differential_summary() is None
        and _check_readme_adversarial_summary() is None
        and _check_readme_vm_review_scope() is None
        and _check_readme_vm_resistance_summary() is None
    )


def test_support_matrix_summarizes_test_evidence_profiles() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    unit_counts = summary["unit_test_evidence_counts"]
    e2e_counts = summary["e2e_test_evidence_counts"]

    expect(
        sum(unit_counts.values()) == len(matrix["passes"])
        and "tests/unit" in unit_counts
        and sum(e2e_counts.values()) >= len(matrix["passes"])
        and "tests/integration" in e2e_counts
    )


def test_pass_maturity_gap_counts_match_generated_summary() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))

    expect(_check_pass_maturity_gap_summary(matrix) is None)


def test_release_contract_current_tree_is_valid() -> None:
    expect(main() == 0)


def test_release_contract_documentation_links_exist() -> None:
    expect(_check_documentation_links() is None)


def test_release_contract_documentation_claims_remain_current() -> None:
    expect(_check_documentation_claims() is None)


def test_release_blockers_track_open_changes_md_gaps() -> None:
    expect(_check_release_blockers() is None)


def test_release_contract_rejects_unknown_release_blocker_id() -> None:
    blockers = (_ROOT / "docs" / "release-blockers.md").read_text(encoding="utf-8")

    rejected = False
    try:
        _validate_release_blockers_text(blockers.replace("RB-007", "RB-999", 1))
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_unlinked_release_blocker() -> None:
    blockers = (_ROOT / "docs" / "release-blockers.md").read_text(encoding="utf-8")

    rejected = False
    try:
        _validate_release_blockers_text(blockers.replace("Evidence map:", "Evidence:", 1))
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_release_blocker_without_exit_criteria() -> None:
    blockers = (_ROOT / "docs" / "release-blockers.md").read_text(encoding="utf-8")

    rejected = False
    try:
        _validate_release_blockers_text(blockers.replace("Exit criteria:", "Closure:", 1))
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_vm_blocker_without_semantic_gap_scope() -> None:
    blockers = (_ROOT / "docs" / "release-blockers.md").read_text(encoding="utf-8")

    rejected = False
    try:
        _validate_release_blockers_text(blockers.replace(" `vm_semantic_gap_scope`", "", 1))
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_incomplete_release_blocker_index() -> None:
    blockers = (_ROOT / "docs" / "release-blockers.md").read_text(encoding="utf-8")

    rejected = False
    try:
        _validate_release_blockers_text(blockers.replace("| RB-006 | VM resistance |", "| RB-006 | VM hardening |", 1))
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_vm_resistance_without_adversarial_validation_scope() -> None:
    blockers = (_ROOT / "docs" / "release-blockers.md").read_text(encoding="utf-8")

    rejected = False
    try:
        _validate_release_blockers_text(blockers.replace(" `adversarial_validation`", "", 1))
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_human_review_blocker_without_release_decision_scope() -> None:
    blockers = (_ROOT / "docs" / "release-blockers.md").read_text(encoding="utf-8")

    rejected = False
    try:
        _validate_release_blockers_text(blockers.replace(" `human_signoff` and `release_decision`", "", 1))
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_overstated_release_claims() -> None:
    claims = _forbidden_release_claims(
        "This is production-ready with full parity and ready to ship. " "VM milestone approved; anti-tamper approved."
    )

    expect(
        claims == ("production-ready", "ready to ship", "full parity", "vm milestone approved", "anti-tamper approved")
    )


def test_independent_review_packet_lists_vm_resistance_reports() -> None:
    packet = (_ROOT / "docs" / "independent-review-packet.md").read_text(encoding="utf-8")

    expect("protection-handler-clustering.json" in packet and "protection-bytecode-grammar.json" in packet)


def test_independent_review_packet_keeps_vm_resistance_checklist() -> None:
    expect(_check_independent_review_packet_claims() is None)


def test_vm_unsupported_instruction_diagnostics_remain_precise() -> None:
    readme = " ".join((_ROOT / "README.md").read_text(encoding="utf-8").split())
    packet = " ".join((_ROOT / "docs" / "independent-review-packet.md").read_text(encoding="utf-8").split())
    fragment = "instruction address, mnemonic, type, size, bounded opcode preview, capability, and reason"

    expect(fragment in readme and fragment in packet)


def test_release_contract_rejects_missing_documentation_link(tmp_path: Path) -> None:
    document = tmp_path / "review.md"
    document.write_text("[missing](missing.json)", encoding="utf-8")

    rejected = False
    try:
        _check_documentation_links((document,))
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_incomplete_runtime_evidence() -> None:
    inventory = json.loads((_ROOT / "docs" / "protection-maturity-corpus.json").read_text(encoding="utf-8"))
    inventory["fixtures"][0]["baseline_runtime"]["status"] = "error"

    rejected = False
    try:
        _validate_inventory(inventory)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_inconsistent_inventory_summary() -> None:
    inventory = json.loads((_ROOT / "docs" / "protection-maturity-corpus.json").read_text(encoding="utf-8"))
    inventory["summary"]["successful_seed_runs"] += 1

    rejected = False
    try:
        _validate_inventory(inventory)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_validates_vm_resistance_artifacts() -> None:
    handler = json.loads((_ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((_ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))

    _validate_vm_resistance_artifacts(handler, bytecode)


def test_release_contract_rejects_vm_handler_similarity_regression() -> None:
    handler = json.loads((_ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((_ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    handler["cross_seed_has_exact_normalised_matches"] = True

    rejected = False
    try:
        _validate_vm_resistance_artifacts(handler, bytecode)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_vm_bytecode_stride_regression() -> None:
    handler = json.loads((_ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((_ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    bytecode["target_stride_diverse"] = False

    rejected = False
    try:
        _validate_vm_resistance_artifacts(handler, bytecode)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_vm_resistance_without_pending_adversarial_scope() -> None:
    handler = json.loads((_ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((_ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    del handler["adversarial_validation"]

    rejected = False
    try:
        _validate_vm_resistance_artifacts(handler, bytecode)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_validates_independent_review_artifact() -> None:
    report = json.loads((_ROOT / "docs" / "independent-review.json").read_text(encoding="utf-8"))

    _validate_independent_review_artifact(report)
    _check_independent_review_artifact()


def test_release_contract_rejects_failed_independent_review_check() -> None:
    report = json.loads((_ROOT / "docs" / "independent-review.json").read_text(encoding="utf-8"))
    report["checks"][0]["status"] = "failed"

    rejected = False
    try:
        _validate_independent_review_artifact(report)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_independent_review_without_vm_block() -> None:
    report = json.loads((_ROOT / "docs" / "independent-review.json").read_text(encoding="utf-8"))
    report["release_decision"]["status"] = "ship"

    rejected = False
    try:
        _validate_independent_review_artifact(report)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_stale_independent_review_artifact() -> None:
    report = json.loads((_ROOT / "docs" / "independent-review.json").read_text(encoding="utf-8"))
    report["checks"][0]["detail"] = "stale detail"

    rejected = False
    try:
        _validate_independent_review_freshness(report)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_requires_versioned_changelog_heading() -> None:
    rejected = False
    try:
        _check_changelog("9.9.9-test")
    except ValueError:
        rejected = True

    expect(rejected)


def test_changelog_keeps_vm_milestone_blocker() -> None:
    changelog = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    expect("VM milestone blocked until external human review" in changelog)


def test_release_workflow_tests_installed_wheel_outside_checkout() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    expect(
        "python -m pip install --force-reinstall dist/*.whl" in workflow
        and "Run tests against installed wheel" in workflow
        and "cp -R .github tests fixtures docs scripts" in workflow
        and 'cd "$test_root"' in workflow
        and "--ignore=tests/unit/test_release_contract.py" not in workflow
        and "python -W error -m pytest --no-cov" in workflow
        and 'awk -v version="$RELEASE_VERSION"' in workflow
        and "test -s /tmp/changes.md" in workflow
    )


def test_release_workflow_requires_green_ci_for_tag_commit() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    expect(
        "Require green CI for release commit" in workflow
        and "--workflow ci.yml" in workflow
        and '--commit "$GITHUB_SHA"' in workflow
        and 'test "$ci_conclusion" = "success"' in workflow
    )


def test_release_workflow_excludes_sbom_from_pypi_upload() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    publish_job = workflow.split("  publish-pypi:", 1)[1].split("  create-release:", 1)[0]

    expect("rm dist/sbom.cdx.json" in publish_job)


def test_release_workflow_downloads_pypi_artifacts_with_repository_context() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    publish_job = workflow.split("  publish-pypi:", 1)[1].split("  create-release:", 1)[0]

    expect('gh run download "$GITHUB_RUN_ID" --repo "$GITHUB_REPOSITORY"' in publish_job)


def test_release_recovery_validates_source_run_and_tag() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "release-recovery.yml").read_text(encoding="utf-8")

    expect(
        'git rev-parse "${RELEASE_TAG}^{commit}"' in workflow
        and "validate-release" in workflow
        and "publish-pypi" in workflow
        and 'gh run download "$SOURCE_RUN_ID" --name dist --dir dist' in workflow
    )


def test_corpus_workflows_run_the_full_pass_selection() -> None:
    adversarial = (_ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")
    differential = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")

    expect(
        "schedule:" in adversarial
        and "workflow_dispatch:" in adversarial
        and "cron:" in adversarial
        and "schedule:" in differential
        and "workflow_dispatch:" in differential
        and "cron:" in differential
        and "--passes all" in adversarial
        and "--require-tool-slots" in adversarial
        and "Validate adversarial campaign summary" in adversarial
        and "expected_tools" in adversarial
        and "observed_tools" in adversarial
        and "binary-ninja" in adversarial
        and "missing_pass_runs" in adversarial
        and "missing_tool_runs" in adversarial
        and "adversarial_evidence_blockers" in adversarial
        and "incomplete_tool_coverage" in adversarial
        and "completed_tool_runs_by_tool" in adversarial
        and "unavailable_tool_runs_by_tool" in adversarial
        and "unavailable_reasons_by_tool" in adversarial
        and "incomplete tool coverage mismatch" in adversarial
        and "passes without applications" in adversarial
        and "--passes all" in differential
        and "--require-complete-evidence" in differential
        and "--count 3" in differential
        and "Validate differential campaign summary" in differential
        and "platform_scope" in differential
        and "platform_gap_scope" in differential
        and "corpus_gap_scope" in differential
        and "corpus_scope" in differential
        and "fixtures/dataset" in differential
        and "missing_corpus_passes" in differential
        and "total_complete_evidence_missing_runs" in differential
        and "passes_with_incomplete_coverage" in differential
        and "continuous_evidence_blockers" in differential
        and "differential-corpus-by-pass" in differential
    )


def test_release_contract_validates_corpus_workflows() -> None:
    expect(_check_corpus_workflows() is None)


def test_ci_runs_generated_support_matrix_freshness_check() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    expect("python scripts/support_matrix.py --check docs/support-matrix.json" in workflow)


def test_independent_review_packet_keeps_binary_ninja_in_benchmark_contract() -> None:
    packet = (_ROOT / "docs" / "independent-review-packet.md").read_text(encoding="utf-8")

    expect("Binary Ninja: measured by the benchmark when its licensed API is available" in packet)
    expect("Binary Ninja remains excluded by project decision" not in packet)
    expect("Binary Ninja is omitted by project decision" not in packet)
