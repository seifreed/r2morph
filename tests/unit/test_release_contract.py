"""Regression tests for the versioned support contract."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.check_release_contract import (
    _check_adversarial_benchmark_evidence,
    _check_changelog,
    _check_corpus_pass_selection_docs,
    _check_corpus_workflows,
    _check_differential_gap_evidence,
    _check_documentation_claims,
    _check_documentation_links,
    _check_independent_review_artifact,
    _check_independent_review_packet_claims,
    _check_matrix,
    _check_maturity_gap_evidence,
    _check_parity_gap_evidence,
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
    _check_vm_resistance_gap_evidence,
    _check_vm_semantic_campaign,
    _check_vm_semantic_fixture_coverage,
    _check_vm_semantic_gap_evidence,
    _forbidden_release_claims,
    _validate_adversarial_benchmark_artifact,
    _validate_angr_runtime_available,
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
_EXPECTED_VM_FIXTURE_COUNT = 151
_EXPECTED_DIFFERENTIAL_BLOCKERS = 5
_EXPECTED_ADVERSARIAL_BLOCKERS = 2
_EXPECTED_TOTAL_MATURITY_BLOCKERS = 12
_EXPECTED_EXTENDED_FALSE_POSITIVE_MEASURED_PASSES = 12
_EXPECTED_ADVERSARIAL_TOOLS = [
    "radare2",
    "objdump",
    "angr",
    "binary-ninja",
    "unicorn",
    "triton",
    "ida-pro",
    "ghidra",
    "custom",
]
_CURRENT_ANGR_EVIDENCE = "docs/protection-adversarial-angr-local-2026-09-20.json"
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


def test_compatibility_corpus_documents_current_generated_variant_count() -> None:
    contract = " ".join((_ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8").split())

    expect(
        "same 200 generated ELF x86-64 variants" in contract
        and "all 200 generated variants" in contract
        and "seventy-two generated" not in contract
    )


def test_differential_workflow_runs_on_relevant_main_pushes() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")

    expect(
        "  push:\n    branches: [main]" in workflow
        and '      - ".github/workflows/ci.yml"' in workflow
        and '      - "docs/pass-maturity.md"' in workflow
        and '      - "docs/release-blockers.md"' in workflow
        and '      - "docs/independent-review-packet.md"' in workflow
        and '      - "r2morph/**"' in workflow
        and '      - "scripts/**"' in workflow
        and '      - "tests/**"' in workflow
    )


def test_differential_workflow_installs_lld_for_real_composition() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    primary_job = workflow.split("  differential-corpus:\n", 1)[1].split("  cross-platform-differential:", 1)[0]

    expect("clang lld" in primary_job and "test_polymorphic_engine_real.py" in primary_job)


def test_independent_review_follows_successful_adversarial_campaign() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "independent-review.yml").read_text(encoding="utf-8")

    expect(
        'workflows: ["Adversarial Analysis Benchmark"]' in workflow
        and "types: [completed]" in workflow
        and "github.event.workflow_run.head_sha || github.sha" in workflow
    )


def test_compatibility_corpus_does_not_promote_historical_six_pass_campaign() -> None:
    contract = " ".join((_ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8").split())

    expect(
        "six selected passes available at that commit" in contract
        and "a full ten-pass campaign is required before this document claims a complete Linux CI record" in contract
    )


def test_local_adversarial_angr_evidence_completes_original_and_protected() -> None:
    report = json.loads(
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-18-59898697.json").read_text(encoding="utf-8")
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


def test_release_contract_rejects_missing_angr_runtime_dependency() -> None:
    rejected = False
    try:
        _validate_angr_runtime_available("linux", lambda _name: None)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_allows_missing_angr_runtime_on_windows() -> None:
    _validate_angr_runtime_available("win32", lambda _name: None)


def test_release_contract_rejects_missing_binary_ninja_slot() -> None:
    report = json.loads(
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-18-59898697.json").read_text(encoding="utf-8")
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
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-18-59898697.json").read_text(encoding="utf-8")
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
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-18-59898697.json").read_text(encoding="utf-8")
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
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-18-59898697.json").read_text(encoding="utf-8")
    )
    del report["release_signoff_blockers"]

    rejected = False
    try:
        _validate_adversarial_benchmark_artifact(report)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_adversarial_benchmark_without_signoff_blocker_totals() -> None:
    report = json.loads(
        (_ROOT / "docs" / "protection-adversarial-angr-local-2026-09-18-59898697.json").read_text(encoding="utf-8")
    )
    del report["release_signoff_blocker_totals"]

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
        and "Not independently measured." not in summary["false_positive_risk_counts"]
        and summary["false_positive_risk_counts"].get(
            "Measured by the scheduled extended maturity pass smoke: native runtime and independent QEMU/Unicorn "
            "semantic false-positive observations are complete and the release gate requires a zero rate."
        )
        == _EXPECTED_EXTENDED_FALSE_POSITIVE_MEASURED_PASSES
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
        and "Not measured per pass." not in summary["performance_counts"]
        and any("scheduled extended maturity pass smoke" in value for value in summary["performance_counts"])
    )


def test_support_matrix_summarizes_instruction_coverage_profiles() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]

    expect(
        sum(summary["instructions_affected_counts"].values()) == len(matrix["passes"])
        and "Not exhaustively catalogued." not in summary["instructions_affected_counts"]
    )


def test_support_matrix_names_maturity_gap_passes() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    gaps = summary["maturity_gap_passes"]

    expect(
        set(gaps) == {"decompiler_effectiveness"}
        and "Not measured per pass." not in summary["performance_counts"]
        and any("scheduled extended maturity pass smoke" in value for value in summary["performance_counts"])
        and len(gaps["decompiler_effectiveness"])
        == summary["decompiler_effectiveness_counts"]["Not independently measured."]
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
        and "performance" not in gaps_by_pass["anti-disassembly"]
        and all(gaps for gaps in gaps_by_pass.values())
    )


def test_support_matrix_names_maturity_evidence_blockers() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    blockers = summary["maturity_evidence_blockers"]

    expect(
        blockers.get("native_evidence_gap_passes", []) == summary["native_evidence_gap_passes"]
        and blockers["missing_fields_by_field"] == summary["maturity_gap_passes"]
        and blockers["missing_fields_by_pass"] == summary["maturity_gaps_by_pass"]
        and "performance" not in blockers["missing_fields_by_field"]
        and "anti-disassembly" in blockers["missing_fields_by_pass"]
    )


def test_support_matrix_names_maturity_gap_evidence() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    evidence = summary["maturity_gap_evidence"]
    expected_fields = set(summary["maturity_gap_passes"])
    if summary["native_evidence_gap_passes"]:
        expected_fields.add("native_evidence")
    evidence_paths = {
        item
        for row in evidence.values()
        for item in row["evidence"]
        if isinstance(item, str) and not item.startswith("http")
    }

    expect(
        set(evidence) == expected_fields
        and (
            ("native_evidence" not in evidence and not summary["native_evidence_gap_passes"])
            or evidence["native_evidence"]["passes"] == summary["native_evidence_gap_passes"]
        )
        and all(row["passes"] for row in evidence.values())
        and all(
            row["status"].endswith("-incomplete") or row["status"].endswith("-unsupported") for row in evidence.values()
        )
        and all((_ROOT / path).exists() for path in evidence_paths)
        and summary["maturity_blocker_totals"]["total_maturity_blockers"] == _EXPECTED_TOTAL_MATURITY_BLOCKERS
    )


def test_release_contract_rejects_missing_maturity_gap_evidence() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["maturity_gap_evidence"].pop("decompiler_effectiveness")

    rejected = False
    try:
        _check_maturity_gap_evidence(matrix)
    except ValueError as error:
        rejected = "maturity gap evidence" in str(error)

    expect(rejected)


def test_release_contract_rejects_stale_maturity_blocker_totals() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["maturity_blocker_totals"]["total_maturity_blockers"] += 1

    rejected = False
    try:
        _check_maturity_gap_evidence(matrix)
    except ValueError as error:
        rejected = "maturity blocker totals" in str(error)

    expect(rejected)


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
    expected = matrix["vm_semantics"]["gap_scope"]

    expect(
        summary["vm_semantic_gap_scope"] == expected
        and summary["vm_semantic_evidence_blockers"]["vm_semantic_gap_scope"] == expected
        and summary["vm_semantic_blocker_totals"]["vm_semantic_gap_scope"] == len(expected)
        and summary["vm_semantic_blocker_totals"]["total_vm_semantic_blockers"] == len(expected)
    )


def test_support_matrix_names_vm_semantic_fixture_coverage() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    coverage = matrix["matrix"]["summary"]["vm_semantic_fixture_coverage"]

    expect(
        coverage == matrix["vm_semantics"]["fixture_coverage"]
        and (_ROOT / coverage["artifact"]).exists()
        and coverage["fixture_count"] == _EXPECTED_VM_FIXTURE_COUNT
        and coverage["covered_capability_count"] == coverage["capability_count"]
        and coverage["unclassified_count"] == 0
        and "memory_addressing" in coverage["capabilities"]
        and "floating_point_and_simd" in coverage["capabilities"]
    )


def test_release_contract_rejects_incomplete_vm_semantic_fixture_coverage() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["vm_semantic_fixture_coverage"]["covered_capability_count"] -= 1
    matrix["vm_semantics"]["fixture_coverage"] = matrix["matrix"]["summary"]["vm_semantic_fixture_coverage"]

    rejected = False
    try:
        _check_vm_semantic_fixture_coverage(matrix)
    except ValueError as error:
        rejected = "vm semantic fixture coverage" in str(error)

    expect(rejected)


def test_support_matrix_names_vm_semantic_gap_evidence_without_signoff() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    evidence = summary["vm_semantic_gap_evidence"]
    gap_scope = summary["vm_semantic_gap_scope"]
    resolved = summary["vm_semantic_resolved_evidence"]

    evidence_paths = [
        item
        for row in evidence.values()
        for item in row["evidence"]
        if isinstance(item, str) and not item.startswith("http")
    ]

    expect(
        sorted(evidence) == sorted(gap_scope)
        and evidence == matrix["vm_semantics"]["gap_evidence"]
        and all(row["status"] == "campaign-measured" for row in resolved.values())
        and resolved == matrix["vm_semantics"]["resolved_evidence"]
        and all((_ROOT / path).exists() for path in evidence_paths)
        and summary["vm_semantic_blocker_totals"]["total_vm_semantic_blockers"] == 0
    )


def test_release_contract_validates_vm_semantic_campaign_artifact() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))

    _check_vm_semantic_campaign(matrix)


def test_release_contract_rejects_missing_vm_semantic_resolved_evidence() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    del matrix["vm_semantics"]["resolved_evidence"]["ssa-liveness"]
    matrix["matrix"] = build_matrix(matrix)

    rejected = False
    try:
        _check_vm_semantic_campaign(matrix)
    except ValueError as error:
        rejected = "vm semantic resolved evidence" in str(error)

    expect(rejected)


def test_release_contract_rejects_stale_vm_semantic_blocker_totals() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["vm_semantic_blocker_totals"]["total_vm_semantic_blockers"] += 1

    rejected = False
    try:
        _check_vm_semantic_gap_evidence(matrix)
    except ValueError as error:
        rejected = "vm semantic blocker totals" in str(error)

    expect(rejected)


def test_support_matrix_names_vm_resistance_gap_scope() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    expected = ["human-adversarial-validation"]

    expect(
        summary["vm_resistance_gap_scope"] == expected
        and summary["vm_resistance_evidence_blockers"]["vm_resistance_gap_scope"] == expected
        and summary["vm_resistance_blocker_totals"]["vm_resistance_gap_scope"] == len(expected)
        and summary["vm_resistance_blocker_totals"]["total_vm_resistance_blockers"] == len(expected)
    )


def test_support_matrix_names_vm_resistance_gap_evidence_without_signoff() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    evidence = summary["vm_resistance_gap_evidence"]
    gap_scope = summary["vm_resistance_gap_scope"]
    evidence_paths = {
        item
        for row in evidence.values()
        for item in row["evidence"]
        if isinstance(item, str) and not item.startswith("http")
    }

    expect(
        sorted(evidence) == sorted(gap_scope)
        and all(row["evidence_quality"] == "automated-adversarial-smoke" for gap, row in evidence.items())
        and all(row["status"] != "complete" for row in evidence.values())
        and all((_ROOT / path).exists() for path in evidence_paths)
        and summary["vm_resistance_blocker_totals"]["total_vm_resistance_blockers"] == len(gap_scope)
    )


def test_support_matrix_records_latest_vm_resistance_campaign() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    evidence = matrix["matrix"]["summary"]["vm_resistance_gap_evidence"]
    latest = "docs/protection-vm-resistance-2026-09-22-e3a491b3.json"

    expect(all(latest in row["evidence"] for row in evidence.values()))


def test_release_contract_rejects_stale_vm_resistance_blocker_totals() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["vm_resistance_blocker_totals"]["total_vm_resistance_blockers"] += 1

    rejected = False
    try:
        _check_vm_resistance_gap_evidence(matrix)
    except ValueError as error:
        rejected = "vm resistance blocker totals" in str(error)

    expect(rejected)


def test_release_contract_rejects_missing_vm_resistance_gap_evidence() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["vm_resistance_gap_evidence"].pop("human-adversarial-validation")

    rejected = False
    try:
        _check_vm_resistance_gap_evidence(matrix)
    except ValueError as error:
        rejected = "vm resistance gap evidence" in str(error)

    expect(rejected)


def test_support_matrix_names_differential_gap_evidence() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    evidence = summary["differential_gap_evidence"]
    evidence_paths = {
        item
        for row in evidence.values()
        for item in row["evidence"]
        if isinstance(item, str) and not item.startswith("http")
    }

    expect(
        summary["differential_evidence_scope"]["platform_scope"]
        == {"os": "linux", "format": "ELF", "architecture": "x86-64"}
        and summary["differential_evidence_scope"]["preview_smoke_scope"]
        == {
            "formats": ["ELF", "Mach-O", "PE"],
            "architectures": ["AArch64", "ARM", "x86"],
            "evidence": [
                ".github/workflows/differential-corpus.yml",
                "tests/integration/test_mutation_nop_insertion_arm64.py",
                "tests/integration/test_platform_deeper.py",
                "tests/integration/test_elf_arm64_native.py",
                "tests/integration/test_elf_x86_32_native.py",
                "tests/integration/test_elf_arm32_native.py",
                "tests/integration/test_platform_tier1_matrix.py",
            ],
            "status": "preview-smoke-only",
        }
        and summary["differential_evidence_blockers"]["platform_gap_scope"]
        == {"formats": ["Mach-O", "PE"], "architectures": ["AArch64", "ARM", "x86"]}
        and summary["differential_evidence_blockers"]["corpus_gap_scope"]
        == {"corpus_families": [], "input_sources": []}
        and summary["differential_blocker_totals"]["total_differential_blockers"] == _EXPECTED_DIFFERENTIAL_BLOCKERS
        and sorted(evidence) == ["corpus_gap_scope", "platform_gap_scope", "platform_scope", "preview_smoke_scope"]
        and all(row["status"] != "complete" for row in evidence.values())
        and all((_ROOT / path).exists() for path in evidence_paths)
    )


def test_release_contract_rejects_missing_differential_gap_evidence() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["differential_gap_evidence"].pop("platform_gap_scope")

    rejected = False
    try:
        _check_differential_gap_evidence(matrix)
    except ValueError as error:
        rejected = "differential gap evidence" in str(error)

    expect(rejected)


def test_release_contract_rejects_stale_differential_blocker_totals() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["differential_blocker_totals"]["total_differential_blockers"] += 1

    rejected = False
    try:
        _check_differential_gap_evidence(matrix)
    except ValueError as error:
        rejected = "differential blocker totals" in str(error)

    expect(rejected)


def test_support_matrix_names_adversarial_benchmark_gaps() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    evidence = summary["adversarial_benchmark_evidence"]
    evidence_paths = {
        item
        for value in evidence.values()
        if isinstance(value, dict)
        for row in value.values()
        if isinstance(row, dict)
        for item in row.get("evidence", [])
        if isinstance(item, str) and not item.startswith("http")
    }
    evidence_paths.update(evidence["campaign_evidence"])

    expect(
        evidence["expected_tools"] == _EXPECTED_ADVERSARIAL_TOOLS
        and evidence["measured_available_tools"]["angr"]["status"] == "completed"
        and evidence["measured_available_tools"]["unicorn"]["status"] == "completed"
        and evidence["measured_available_tools"]["ghidra"]["status"] == "completed"
        and evidence["measured_available_tools"]["ida-pro"]["status"] == "completed"
        and evidence["measured_available_tools"]["triton"]["status"] == "completed"
        and evidence["unavailable_reference_tools"]["binary-ninja"]["status"] == "unavailable"
        and "binary-ninja" in summary["adversarial_evidence_blockers"]["binary_ninja_unavailable"]
        and "binary-ninja" not in summary["adversarial_evidence_blockers"]["incomplete_tool_coverage"]
        and "angr" not in summary["adversarial_evidence_blockers"]["incomplete_tool_coverage"]
        and "unicorn" not in summary["adversarial_evidence_blockers"]["incomplete_tool_coverage"]
        and "ghidra" not in summary["adversarial_evidence_blockers"]["incomplete_tool_coverage"]
        and "ida-pro" not in summary["adversarial_evidence_blockers"]["incomplete_tool_coverage"]
        and "triton" not in summary["adversarial_evidence_blockers"]["incomplete_tool_coverage"]
        and summary["adversarial_blocker_totals"]["total_adversarial_blockers"] == _EXPECTED_ADVERSARIAL_BLOCKERS
        and all((_ROOT / path).exists() for path in evidence_paths)
    )


def test_support_matrix_records_current_angr_corpus_evidence() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    evidence = matrix["matrix"]["summary"]["adversarial_benchmark_evidence"]
    angr_evidence = evidence["measured_available_tools"]["angr"]["evidence"]

    expect(_CURRENT_ANGR_EVIDENCE in angr_evidence)


def test_release_contract_rejects_missing_binary_ninja_adversarial_slot() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["adversarial_benchmark_evidence"]["unavailable_reference_tools"].pop("binary-ninja")

    rejected = False
    try:
        _check_adversarial_benchmark_evidence(matrix)
    except ValueError as error:
        rejected = "Binary Ninja" in str(error)

    expect(rejected)


def test_release_contract_rejects_stale_adversarial_blocker_totals() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["adversarial_blocker_totals"]["total_adversarial_blockers"] += 1

    rejected = False
    try:
        _check_adversarial_benchmark_evidence(matrix)
    except ValueError as error:
        rejected = "adversarial blocker totals" in str(error)

    expect(rejected)


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


def test_support_matrix_classifies_non_official_parity_evidence() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    evidence = summary["parity_gap_evidence"]
    preview_targets = evidence["preview_evidence_targets"]
    zero_targets = evidence["zero_evidence_targets"]

    expect(
        sum(row["evidenced_cells"] for row in preview_targets) == summary["non_official_evidenced_cells"]
        and len(preview_targets) + len(zero_targets) == len(summary["non_official_gap_targets"])
        and all(row["evidenced_cells"] > 0 for row in preview_targets)
        and all(row["evidenced_cells"] == 0 for row in zero_targets)
        and {(row["format"], row["architecture"]) for row in preview_targets}
        == {
            ("ELF", "ARM"),
            ("ELF", "AArch64"),
            ("ELF", "x86"),
            ("Mach-O", "AArch64"),
            ("Mach-O", "x86-64"),
            ("PE", "x86-64"),
        }
    )


def test_support_matrix_names_parity_evidence_blockers() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    summary = matrix["matrix"]["summary"]
    blockers = summary["parity_evidence_blockers"]
    totals = summary["parity_blocker_totals"]

    expect(
        blockers["parity_gap_scope"] == summary["parity_gap_scope"]
        and blockers["non_official_gap_targets"] == summary["non_official_gap_targets"]
        and totals["non_official_gap_targets"] == len(summary["non_official_gap_targets"])
        and totals["parity_gap_formats"] == len(summary["parity_gap_scope"]["formats"])
        and totals["parity_gap_architectures"] == len(summary["parity_gap_scope"]["architectures"])
        and totals["total_parity_blockers"]
        == totals["non_official_gap_targets"] + totals["parity_gap_formats"] + totals["parity_gap_architectures"]
        and all(
            target["evidence_percent"] < summary["official_evidence_percent"]
            for target in blockers["non_official_gap_targets"]
        )
    )


def test_release_contract_rejects_missing_parity_gap_evidence() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["parity_gap_evidence"]["zero_evidence_targets"].pop()

    rejected = False
    try:
        _check_parity_gap_evidence(matrix)
    except ValueError as error:
        rejected = "parity gap evidence" in str(error)

    expect(rejected)


def test_release_contract_rejects_stale_parity_blocker_totals() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["matrix"]["summary"]["parity_blocker_totals"]["total_parity_blockers"] += 1

    rejected = False
    try:
        _check_parity_gap_evidence(matrix)
    except ValueError as error:
        rejected = "parity blocker totals" in str(error)

    expect(rejected)


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
    matrix["maturity"]["profiles"]["polymorphic-engine-instruction-catalogued"]["performance"] = ""
    matrix["matrix"] = build_matrix(matrix)

    rejected = False
    try:
        _check_matrix(matrix, matrix["release"])
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_missing_maturity_evidence_path() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix["maturity"]["profiles"]["polymorphic-engine-instruction-catalogued"]["unit_tests"] = [
        "tests/missing-unit-evidence"
    ]
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
        sum(unit_counts.values()) >= len(matrix["passes"])
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


def test_release_contract_rejects_release_blockers_without_totals() -> None:
    blockers = (_ROOT / "docs" / "release-blockers.md").read_text(encoding="utf-8")

    total_fields = (
        " `maturity_blocker_totals`",
        " `continuous_evidence_blocker_totals`",
        " `vm_semantic_blocker_totals`",
        " `parity_blocker_totals`",
        " `adversarial_evidence_blocker_totals`",
        " `vm_resistance_blocker_totals`",
    )
    rejected_count = 0
    for field in total_fields:
        try:
            _validate_release_blockers_text(blockers.replace(field, "", 1))
        except ValueError:
            rejected_count += 1

    expect(rejected_count == len(total_fields))


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


def test_release_contract_rejects_vm_handler_similarity_rate_regression() -> None:
    handler = json.loads((_ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((_ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    handler["cross_seed_nearest_similarity_above_threshold_percent"] = 100.0

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


def test_release_contract_rejects_vm_bytecode_stride_value_regression() -> None:
    handler = json.loads((_ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((_ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    bytecode["target_stride_values"] = [3, 4, 6]

    rejected = False
    try:
        _validate_vm_resistance_artifacts(handler, bytecode)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_vm_bytecode_target_operation_regression() -> None:
    handler = json.loads((_ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((_ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    bytecode["target_operation"] = {"is_immediate": True, "mnemonic": "xor", "width": 32}

    rejected = False
    try:
        _validate_vm_resistance_artifacts(handler, bytecode)
    except ValueError:
        rejected = True

    expect(rejected)


def test_release_contract_rejects_vm_padding_diversity_regression() -> None:
    handler = json.loads((_ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((_ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    bytecode["padding_histogram"] = {"0": bytecode["total_handlers"]}

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


def test_release_contract_rejects_independent_review_without_human_review_reason() -> None:
    report = json.loads((_ROOT / "docs" / "independent-review.json").read_text(encoding="utf-8"))
    report["release_decision"]["reason"] = "automated checks are sufficient"

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
        and 'workflows: ["Differential Corpus By Pass"]' in adversarial
        and "github.event.workflow_run.head_sha || github.sha" in adversarial
        and "github.event.workflow_run.conclusion == 'success'" in adversarial
        and "always() && !cancelled() && (github.event_name != 'workflow_run'" in adversarial
        and "Build and install package wheel" in adversarial
        and "sudo apt-get install -y git build-essential clang" in adversarial
        and "Build and install package wheel" in differential
        and "python -m build" in adversarial
        and "python -m build" in differential
        and "python -m pip install --force-reinstall dist/*.whl" in adversarial
        and "python -m pip install --force-reinstall dist/*.whl" in differential
        and "wheel_root=/tmp/r2morph-adversarial-wheel-check" in adversarial
        and "wheel_root=/tmp/r2morph-differential-wheel-check" in differential
        and "cp -R scripts tests fixtures" in adversarial
        and "cp -R scripts tests fixtures" in differential
        and 'pyproject.toml "$wheel_root"/' in adversarial
        and 'pyproject.toml "$wheel_root"/' in differential
        and 'cd "$wheel_root"' in adversarial
        and 'cd "$wheel_root"' in differential
        and '--output "$GITHUB_WORKSPACE/adversarial-benchmark.json"' in adversarial
        and '--output "$GITHUB_WORKSPACE/differential-corpus.json"' in differential
        and '--output "$GITHUB_WORKSPACE/extended-maturity-passes.json"' in differential
        and "--passes all" in adversarial
        and "--generated-corpus" in adversarial
        and "--require-tool-slots" in adversarial
        and "Validate adversarial campaign summary" in adversarial
        and "expected_tools" in adversarial
        and "observed_tools" in adversarial
        and "binary-ninja" in adversarial
        and "missing_pass_runs" in adversarial
        and "missing_tool_runs" in adversarial
        and "angr campaign is incomplete" in adversarial
        and 'summary["unavailable_tool_runs_by_tool"].get("angr", 0)' in adversarial
        and 'summary["error_tool_runs_by_tool"].get("angr", 0)' in adversarial
        and "adversarial_evidence_blockers" in adversarial
        and "total_adversarial_evidence_blockers" in adversarial
        and "incomplete_tool_coverage" in adversarial
        and "tools_without_full_completion" in adversarial
        and "completed_tool_runs_by_tool" in adversarial
        and "unavailable_tool_runs_by_tool" in adversarial
        and "unavailable_reasons_by_tool" in adversarial
        and "generated_fixture_count" in adversarial
        and "generated_fixture_names" in adversarial
        and "adversarial fixture manifest drift" in adversarial
        and "incomplete tool coverage mismatch" in adversarial
        and "passes without applications" in adversarial
        and "--fixture-shard-count 8" in adversarial
        and "Run VM resistance seed-diversity smoke" in adversarial
        and "scripts/protection_handler_clustering.py" in adversarial
        and '--output "$GITHUB_WORKSPACE/vm-resistance-seed-diversity.json"' in adversarial
        and "Validate VM resistance seed-diversity evidence" in adversarial
        and "pending-human-adversarial-review" in adversarial
        and "cross_seed_has_exact_normalised_matches" in adversarial
        and "cross_seed_largest_normalised_cluster" in adversarial
        and "cross_seed_nearest_similarity_mean" in adversarial
        and "similarity_threshold" in adversarial
        and 'cp -R docs "$wheel_root"/' in adversarial
        and "test_protection_bytecode_grammar.py" in adversarial
        and "test_protection_handler_clustering.py" in adversarial
        and "test_resistance_measurement_contract.py" in adversarial
        and "scripts/vm_resistance_adversarial.py" in adversarial
        and "test_vm_resistance_adversarial.py" in adversarial
        and '--output "$GITHUB_WORKSPACE/vm-resistance-adversarial.json"' in adversarial
        and "if len(cases) != 10:" in adversarial
        and "automated VM resistance evidence is missing" in adversarial
        and "dispatcher_unique_count" in adversarial
        and "tamper_diverged" in adversarial
        and "growth_observed" in adversarial
        and "Upload VM resistance seed-diversity evidence" in adversarial
        and "vm-resistance-seed-diversity" in adversarial
        and "--passes all" in differential
        and "--require-complete-evidence" in differential
        and "--generated-inputs" in differential
        and "--generated-corpus" in differential
        and "--count 1" in differential
        and "--fixture-shard-count 16" in differential
        and "expected_shards = 48" in differential
        and "if len(paths) != 24:" in differential
        and "--fixture-shard-index" in differential
        and "Validate differential campaign summary" in differential
        and "platform_scope" in differential
        and "platform_gap_scope" in differential
        and "corpus_gap_scope" in differential
        and "corpus_scope" in differential
        and "fixtures/dataset" in differential
        and "generated_fixture_count" in differential
        and "generated_fixture_names" in differential
        and 'report["fixture_names"] != expected_fixture_names' in differential
        and "missing_corpus_passes" in differential
        and "total_complete_evidence_missing_runs" in differential
        and "passes_with_incomplete_coverage" in differential
        and "continuous_evidence_blockers" in differential
        and "unexpected continuous evidence blockers" in differential
        and "differential-corpus-by-pass" in differential
        and "Run cross-format differential smoke" in differential
        and "test_binary_rewriter_formats_real.py" in differential
        and "test_binary_rewriter_noop_preserves_real_format" in differential
        and "test_platform_deeper.py" in differential
        and "test_platform_tier1_matrix.py" in differential
        and "test_tier1_pass_preview_target_preserves_exit_code" in differential
        and "if len(cases) != 72" in differential
        and "cross-format-differential.xml" in differential
        and "Validate cross-format differential evidence" in differential
        and "cross-format smoke coverage drift" in differential
        and "platform_requirements" in differential
        and "cross-format platform coverage drift" in differential
        and "Upload cross-format differential evidence" in differential
        and "cross-format-differential" in differential
        and "Run composition regression smoke" in differential
        and "test_polymorphic_engine_real.py" in differential
        and "Run VM semantic regression smoke" in differential
        and "test_memory_width_fixture_virtualization_preserves_exit_code" in differential
        and "test_virtualized_callee_saved_fixture_preserves_registers" in differential
        and "test_call_flags_stack_fixture_virtualization_preserves_exit_code" in differential
        and "test_virtualized_elf_preserves_fs_relative_access" in differential
        and "test_virtualized_threads_tls_and_signal_preserve_exit_code" in differential
        and "test_virtualized_elf_preserves_integer_varargs_stack_abi" in differential
        and "test_virtualized_elf_preserves_floating_point_varargs_register_and_stack_abi" in differential
        and "test_virtualized_direct_call_to_separate_function_preserves_exit_code" in differential
        and "test_virtualized_local_indirect_call_preserves_exit_code" in differential
        and "test_virtualized_vex_nondestructive_packed_add_preserves_result" in differential
        and "test_simd_integer_fixture_virtualization_preserves_exit_code" in differential
        and "test_code_virtualization_preserves_exception_from_call_inside_virtualized_function" in differential
        and "tests/unit/test_code_virtualization_static_dataflow.py" in differential
        and '--junitxml="$GITHUB_WORKSPACE/vm-semantic-differential.xml"' in differential
        and "Validate VM semantic differential evidence" in differential
        and "VM semantic smoke ran too few cases" in differential
        and "VM semantic smoke coverage drift" in differential
        and "Upload VM semantic differential evidence" in differential
        and "vm-semantic-differential.xml" in differential
        and "vm-semantic-differential" in differential
        and "Run parser and rewriter fuzz smoke" in differential
        and "Validate parser and rewriter fuzz smoke" in differential
        and "scripts/continuous_fuzz.py" in differential
        and "--cases 64" in differential
        and "--max-payload 512" in differential
        and "differential-fuzz-smoke.json" in differential
        and "binary_parsers" in differential
        and "vm_dispatcher" in differential
        and "relocations" in differential
        and "binary_rewriter" in differential
        and "Upload differential fuzz smoke" in differential
        and "differential-fuzz-smoke" in differential
        and "Run extended maturity pass smoke" in differential
        and "Validate extended maturity pass smoke" in differential
        and "EXTENDED_MATURITY_PASSES" in differential
        and 'required_metrics = {"output_size", "runtime_duration", "static_metric", "transform_duration"}'
        in differential
        and "extended maturity performance metrics are incomplete" in differential
        and "extended maturity performance coverage is incomplete" in differential
        and "passes_with_missing_affected_instruction_evidence" in differential
        and "missing affected-instruction evidence" in differential
        and "AntiDisassembly,APIHashing,CodeMobility,DataFlowMutation" in differential
        and "SelfModifyingCode,ShortJumpPatching" in differential
        and "missing_extended_passes" in differential
        and "passes_without_extended_applied_runs" in differential
        and "extended_passes_with_error_runs" in differential
        and "extended_maturity_evidence_blockers" in differential
        and "total_extended_maturity_evidence_blockers" in differential
        and "extended maturity pass errors" in differential
        and "extended-maturity-passes" in differential
        and "extended-maturity-merged.json" in differential
        and "public-compatibility-corpus:" in differential
        and "repository: seifreed/r2morph-corpus" in differential
        and "5f16a6fdcccbe2c3c97100f339a68ab916ca2e19" in differential
        and "Build public compatibility corpus" in differential
        and "Run public differential matrix" in differential
        and "Validate public differential matrix" in differential
        and "Run public static recovery benchmark" in differential
        and "Select bounded public corpus matrix" in differential
        and "public-corpus/build-selected" in differential
        and '"O0", "non-pie", "symbols", "dynamic"' in differential
        and '"O1", "non-pie", "symbols", "dynamic"' in differential
        and '"Os", "non-pie", "symbols", "dynamic"' in differential
        and '"variant_count": len(' in differential
        and 'selected_manifest["selection"]["variant_count"] != len(variants)' in differential
        and "public-compatibility-corpus" in differential
        and "Download public compatibility evidence" in differential
        and "public-compatibility-merged.json" in differential
        and "vm-semantic-campaign-aggregate" in differential
        and "Download VM semantic campaign evidence" in differential
        and "VM semantic campaign evidence is incomplete" in differential
        and "public corpus pass selection drift" in differential
        and "public static recovery benchmark is incomplete" in differential
        and 'Path("public-corpus-reports").glob("**/results/matrix.json")' in differential
        and 'Path("public-corpus-reports").glob("**/results/tools.json")' in differential
        and "aggregate-platform-differential:" in differential
        and "Aggregate platform differential evidence" in differential
        and "cross-platform-differential-macos-arm64" in differential
        and "cross-platform-differential-windows-pe" in differential
        and "elf-arm64-native" in differential
        and "elf-x86-32-native" in differential
        and "differential-platform-aggregate" in differential
        and "Validate aggregated platform evidence" in differential
    )


def test_release_contract_validates_corpus_workflows() -> None:
    expect(_check_corpus_workflows() is None)


def test_windows_pe_differential_covers_native_mutation_and_composition_passes() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    windows_job = workflow.split("  cross-platform-format-windows:", 1)[1].split("  public-compatibility-corpus:", 1)[0]

    expect(
        "$cases.Count -ne 11" in windows_job
        and "test_nop_insertion_pe_x86_64_preserves_repaired_integrity" in windows_job
        and "test_instruction_substitution_pe_fixture_preserves_windows_exit_code" in windows_job
        and "test_register_substitution_pe_x86_64_preserves_native_execution" in windows_job
        and "test_constant_unfolding_pe_x86_64_preserves_native_execution" in windows_job
        and "test_tier1_pass_composition_pe_x86_64_preserves_native_execution" in windows_job
        and "test_multiple_mutation_passes_on_x86_binary" in windows_job
    )


def test_adversarial_workflow_covers_fifteen_vm_resistance_shapes() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")
    resistance_job = workflow.split("      - name: Run VM tamper and progressive protection smoke\n", 1)[1].split(
        "      - name: Validate VM tamper and progressive protection smoke\n", 1
    )[0]

    expect(
        'report["fixture_count"] != 15' in workflow
        and all(
            f"--fixture fixtures/dataset/{name}" in resistance_job
            for name in (
                "elf_vm_shift_x86_64",
                "elf_vm_bigimm_x86_64",
                "elf_vm_call_x86_64",
                "elf_vm_icall_x86_64",
                "elf_vm_varargs_x86_64",
                "elf_vm_memwidth_x86_64",
                "elf_vm_tls_x86_64",
                "elf_vm_unwind_x86_64",
                "elf_vm_multiexit_x86_64",
                "elf_vm_simdint_x86_64",
            )
        )
        and "--generated-corpus" in resistance_job
    )


def test_adversarial_workflow_runs_vm_resistance_once_per_campaign() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")
    vm_steps = (
        "Run VM resistance seed-diversity smoke",
        "Validate VM resistance seed-diversity evidence",
        "Run VM tamper and progressive protection smoke",
        "Validate VM tamper and progressive protection smoke",
        "Upload VM tamper and progressive protection smoke",
        "Upload VM resistance seed-diversity evidence",
        "Upload VM resistance bytecode grammar evidence",
    )

    expect(
        all(
            "if: always() && !cancelled() && matrix.fixture_shard == 0"
            in workflow.split(f"      - name: {step}\n", maxsplit=1)[1].split("      - name:", maxsplit=1)[0]
            for step in vm_steps
        )
    )


def test_adversarial_workflow_provisions_reproducible_ghidra() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")

    expect(
        "actions/setup-java@v4" in workflow
        and 'java-version: "21"' in workflow
        and "actions/cache@v4" in workflow
        and "GHIDRA_HEADLESS=$ghidra_dir/support/analyzeHeadless" in workflow
        and "sha256sum --check" in workflow
        and "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54" in workflow
    )


def test_adversarial_workflow_allows_full_campaign_to_finish() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")
    benchmark_job = workflow.split("  benchmark:\n", 1)[1].split("    steps:\n", 1)[0]

    expect("timeout-minutes: 360" in benchmark_job)


def test_differential_merge_step_closes_python_heredoc() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    merge_step = workflow.split("      - name: Merge and validate campaign evidence\n", 1)[1].split(
        "      - name: Build per-pass maturity evidence document\n", 1
    )[0]

    expect(merge_step.rstrip().endswith("          PY"))


def test_vm_semantic_merge_step_closes_python_heredoc() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    merge_step = workflow.split("      - name: Merge and validate VM semantic campaign\n", 1)[1].split(
        "      - name: Upload merged VM semantic campaign evidence\n", 1
    )[0]

    expect(merge_step.rstrip().endswith("          PY"))


def test_continuous_fuzz_workflow_runs_against_installed_wheel() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "fuzz.yml").read_text(encoding="utf-8")

    expect(
        "Build and install package wheel" in workflow
        and "python -m build" in workflow
        and "python -m pip install --force-reinstall dist/*.whl" in workflow
        and "wheel_root=/tmp/r2morph-fuzz-wheel-check" in workflow
        and 'cp -R scripts fixtures "$wheel_root"/' in workflow
        and 'cd "$wheel_root"' in workflow
        and 'python -c "import r2morph; print(r2morph.__file__)"' in workflow
        and '--output "$GITHUB_WORKSPACE/fuzz-campaign.json"' in workflow
        and "Validate continuous fuzz campaign" in workflow
        and "CASES: ${{ inputs.cases || '5000' }}" in workflow
        and "if: always()" in workflow
    )


def test_ci_runs_generated_support_matrix_freshness_check() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    expect("python scripts/support_matrix.py --check docs/support-matrix.json" in workflow)


def test_ci_core_tests_install_arm_emulator() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    core_tests = workflow.split("  stable-tests:", 1)[1].split("  unit-tests:", 1)[0]

    expect("qemu-user" in core_tests)


def test_ci_cross_platform_smoke_runs_against_installed_wheel() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    cross_platform_job = workflow.split("  cross-platform-tests:", 1)[1].split("  package-smoke:", 1)[0]

    expect(
        "Run cross-platform package smoke tests" in cross_platform_job
        and "timeout-minutes: 60" in cross_platform_job
        and "Install build backend for cross-platform wheel smoke" in cross_platform_job
        and "Install radare2 (Windows)" in cross_platform_job
        and '"https://github.com/radareorg/radare2/releases/download/$version/$archiveName"' in cross_platform_job
        and '"adb1ffd158066ea41316fa33b6d23b362aa9258df800721f7d15a42eefdd9202"' in cross_platform_job
        and "Get-FileHash -Algorithm SHA256" in cross_platform_job
        and "Expand-Archive -Path $archive -DestinationPath $destination -Force" in cross_platform_job
        and "$env:GITHUB_PATH" in cross_platform_job
        and 'run: python -m pip install "build>=1.2.0"' in cross_platform_job
        and "shell: bash" in cross_platform_job
        and "python -m build" in cross_platform_job
        and "python -m pip install --force-reinstall dist/*.whl" in cross_platform_job
        and "import platform" in cross_platform_job
        and 'tempfile.mkdtemp(prefix="r2morph-cross-platform-wheel-")' in cross_platform_job
        and 'for name in ("tests", "fixtures", "scripts", "docs", "README.md", "pyproject.toml")' in cross_platform_job
        and 'subprocess.run([sys.executable, "-c", "import r2morph; print(r2morph.__file__)"]' in cross_platform_job
        and "test_targets = [" in cross_platform_job
        and 'if platform.system() != "Windows":' in cross_platform_job
        and '"tests/integration/test_binary_rewriter_formats_real.py"' in cross_platform_job
        and '"tests/integration/test_platform_deeper.py"' in cross_platform_job
        and "x64_assembler_targets = [" in cross_platform_job
        and 'if platform.machine().lower() in {"amd64", "x86_64"}:' in cross_platform_job
        and '"tests/unit/test_circular_imports.py"' in cross_platform_job
        and '"tests/unit/test_cli_basic_commands.py::test_cli_version_function"' in cross_platform_job
        and '"tests/unit/test_pe_handler_parsing_contract.py"' in cross_platform_job
        and '"tests/unit/test_pe_handler_struct_parse.py"' in cross_platform_job
        and '"tests/unit/test_macho_parse_basic.py"' in cross_platform_job
        and '"tests/unit/test_instruction_substitution_arm64_contract.py"' in cross_platform_job
        and '"tests/unit/test_package_data.py"' in cross_platform_job
        and '"tests/unit/test_support_matrix_contract.py"' in cross_platform_job
        and '"tests/unit/test_benchmark_metrics_contract.py"' in cross_platform_job
        and '"tests/unit/test_benchmark_runners_contract.py"' in cross_platform_job
        and '"tests/unit/test_benchmark_reporting_summary_contract.py"' in cross_platform_job
        and '"tests/unit/test_benchmark_reporting_breakdown_contract.py"' in cross_platform_job
        and '"tests/unit/test_benchmark_reporting_text_contract.py"' in cross_platform_job
        and '"tests/unit/test_benchmark_reporting_io_contract.py"' in cross_platform_job
        and '"tests/unit/test_benchmark_reporting_exports_contract.py"' in cross_platform_job
        and '"tests/unit/test_performance_regression_suite_contract.py"' in cross_platform_job
        and '"tests/unit/test_performance_regression_measurement_contract.py"' in cross_platform_job
        and '"tests/unit/test_performance_regression_execution_contract.py"' in cross_platform_job
        and '"tests/unit/test_performance_regression_models_contract.py"' in cross_platform_job
        and '"tests/unit/test_performance_regression_metadata_contract.py"' in cross_platform_job
        and '"tests/unit/test_performance_regression_comparison_contract.py"' in cross_platform_job
        and '"tests/unit/test_performance_regression_storage_contract.py"' in cross_platform_job
        and '"tests/unit/test_pass_dependency_catalogs_contract.py"' in cross_platform_job
        and '"tests/unit/test_evasion_scorer_helpers_contract.py"' in cross_platform_job
        and '"tests/unit/test_enhanced_analyzer_reporting_contract.py"' in cross_platform_job
        and '"tests/unit/test_mutation_annotator_instruction_contract.py"' in cross_platform_job
        and '"tests/unit/test_code_virtualization_memory_widths.py"' in cross_platform_job
        and '"tests/unit/test_code_virtualization_call_abi.py"' in cross_platform_job
        and '"tests/unit/test_code_virtualization_tls.py"' in cross_platform_job
        and '"tests/unit/test_code_virtualization_static_dataflow.py"' in cross_platform_job
        and '"tests/unit/test_code_virtualization_diagnostics.py"' in cross_platform_job
        and '"tests/unit/test_code_virtualization_fp_indexed_shapes.py"' in cross_platform_job
        and '"tests/unit/test_code_virtualization_avx256.py"' in cross_platform_job
    )


def test_differential_workflow_keeps_windows_pe_evidence() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    windows_job = workflow.split("  cross-platform-format-windows:", 1)[1].split("  public-compatibility-corpus:", 1)[0]

    expect(
        "runs-on: windows-latest" in windows_job
        and "test_platform_handlers_deeper_real_more.py" in windows_job
        and "test_platform_handlers_extended.py" in windows_job
        and "test_platform_handlers_real.py" in windows_job
        and "nop_insertion_pe_x86_64_preserves_repaired_integrity" in windows_job
        and "instruction_expansion_pe_x86_64_preserves_native_execution" in windows_job
        and "register_substitution_pe_x86_64_preserves_native_execution" in windows_job
        and "constant_unfolding_pe_x86_64_preserves_native_execution" in windows_job
        and "tier1_pass_composition_pe_x86_64_preserves_native_execution" in windows_job
        and "expected 11" in windows_job
        and "test_pe_handler_checksum_and_imports" in windows_job
        and "test_instruction_substitution_pe_fixture_preserves_windows_exit_code" in windows_job
        and "test_multiple_mutation_passes_on_x86_binary" in windows_job
        and "windows-format-differential.xml" in windows_job
        and 'SelectNodes("//testcase")' in windows_job
        and 'SelectNodes("//failure")' in windows_job
        and 'SelectNodes("//skipped")' in windows_job
        and "cross-platform-differential-windows-pe" in windows_job
    )


def test_evidence_workflow_artifacts_are_rerun_safe() -> None:
    differential_workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    adversarial_workflow = (_ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")

    expect(
        "${{ github.run_id }}-${{ github.run_attempt }}" in differential_workflow
        and "${{ github.run_id }}-${{ github.run_attempt }}" in adversarial_workflow
    )


def test_differential_workflow_keeps_main_campaigns_running() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")

    expect("group: differential-corpus-${{ github.ref }}" in workflow and "cancel-in-progress: true" in workflow)


def test_platform_evidence_aggregate_runs_after_failed_dependencies() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    aggregate_header = workflow.split("  aggregate-platform-differential:\n", 1)[1].split("    needs:", 1)[0]

    expect("if: ${{ always() && !cancelled() }}" in aggregate_header)


def test_independent_review_packet_keeps_binary_ninja_in_benchmark_contract() -> None:
    packet = (_ROOT / "docs" / "independent-review-packet.md").read_text(encoding="utf-8")

    expect("Binary Ninja: measured by the benchmark when its licensed API is available" in packet)
    expect("Binary Ninja remains excluded by project decision" not in packet)
    expect("Binary Ninja is omitted by project decision" not in packet)
