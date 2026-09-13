"""Regression tests for the versioned support contract."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.check_release_contract import _check_changelog, _check_documentation_links, _validate_inventory, main
from scripts.protection_maturity_baseline import CORPUS_PASS_NAMES
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MIN_CONCRETE_PASSES = 20
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
    cli_aliases = matrix["selection"]["cli_aliases"]
    engine_only = set(matrix["selection"]["engine_only_passes"])

    expect(
        set(cli_aliases.values()) | engine_only == pass_names
        and set(cli_aliases) == {"nop", "substitute", "register", "expand", "block"}
        and not (set(cli_aliases.values()) & engine_only)
    )


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

    expect(all(f"`{pass_name}`" in contract for pass_name in CORPUS_PASS_NAMES))
    expect("broad corpus evidence is pending" not in contract)


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


def test_release_contract_current_tree_is_valid() -> None:
    expect(main() == 0)


def test_release_contract_documentation_links_exist() -> None:
    expect(_check_documentation_links() is None)


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


def test_release_contract_requires_versioned_changelog_heading() -> None:
    rejected = False
    try:
        _check_changelog("9.9.9-test")
    except ValueError:
        rejected = True

    expect(rejected)


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
        "--passes all" in adversarial
        and "--passes all" in differential
        and "--count 1" in differential
        and "differential-corpus-by-pass" in differential
    )


def test_independent_review_packet_keeps_binary_ninja_in_benchmark_contract() -> None:
    packet = (_ROOT / "docs" / "independent-review-packet.md").read_text(encoding="utf-8")

    expect("Binary Ninja: measured by the benchmark when its licensed API is available" in packet)
    expect("Binary Ninja remains excluded by project decision" not in packet)
    expect("Binary Ninja is omitted by project decision" not in packet)
