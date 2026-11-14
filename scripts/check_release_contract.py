"""Validate the versioned support and release contract."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib

try:
    from scripts.one_zero_release_gate import check_one_zero_release_gate as _check_one_zero_release_gate
except ModuleNotFoundError:
    from one_zero_release_gate import check_one_zero_release_gate as _check_one_zero_release_gate

try:
    from scripts.release_contract_common import (
        _BANNED_BINARY_NINJA_OMISSION_PHRASES,
        _DOCUMENTATION_LINK_FILES,
        _FORBIDDEN_RELEASE_CLAIMS,
        _MARKDOWN_LINK_PATTERN,
        _RELEASE_BLOCKER_FRAGMENTS,
        _RELEASE_BLOCKER_ID_PATTERN,
        _RELEASE_BLOCKER_IDS,
        _RELEASE_BLOCKER_INDEX_AREAS,
        _RELEASE_BLOCKER_REQUIRED_ENTRY_COUNT,
        _RELEASE_HONESTY_FILES,
        ADVERSARIAL_TOOL_SLOTS,
        FULL_EVIDENCE_PERCENT,
        INDEPENDENT_REVIEW_CHECKS,
        MAXIMUM_VM_HANDLER_SIMILARITY_ABOVE_THRESHOLD_PERCENT,
        MINIMUM_COVERAGE_PERCENT,
        MINIMUM_VM_VARIANT_COUNT,
        PUBLIC_CLI_ALIASES,
        REQUIRED_CI_JOBS,
        REQUIRED_VM_TARGET_OPERATION,
        REQUIRED_VM_TARGET_STRIDE_VALUES,
        ROOT,
        TIER_1_MATURITY_PROFILE,
        VM_ADVERSARIAL_VALIDATION,
        VM_HANDLER_COUNT,
        VM_RESISTANCE_EVIDENCE_QUALITY,
        VM_RESISTANCE_SEED_COUNT,
        Path,
        _check_version,
    )
except ModuleNotFoundError:
    from release_contract_common import (
        ROOT,
        _check_version,
    )


try:
    from scripts.release_contract_matrix import (
        _check_adversarial_benchmark_evidence,
        _check_differential_gap_evidence,
        _check_matrix,
        _check_maturity_gap_evidence,
        _check_maturity_profile_values,
        _check_parity_gap_evidence,
        _check_pass_selection_contract,
        _check_tier_1_maturity,
        _check_vm_resistance_gap_evidence,
        _check_vm_semantic_campaign,
        _check_vm_semantic_campaign_capabilities,
        _check_vm_semantic_fixture_coverage,
        _check_vm_semantic_gap_evidence,
        _load_matrix,
    )
except ModuleNotFoundError:
    from release_contract_matrix import (
        _check_matrix,
        _load_matrix,
    )


try:
    from scripts.release_contract_docs import (
        _check_changelog,
        _check_corpus_pass_selection_docs,
        _check_documentation_claims,
        _check_documentation_links,
        _check_pass_maturity_gap_summary,
        _check_readme_adversarial_summary,
        _check_readme_cross_platform_parity,
        _check_readme_differential_summary,
        _check_readme_pass_surface,
        _check_readme_support_summary,
        _check_readme_vm_resistance_summary,
        _check_readme_vm_review_scope,
        _check_release_blockers,
        _forbidden_release_claims,
        _validate_release_blockers_text,
    )
except ModuleNotFoundError:
    from release_contract_docs import (
        _check_changelog,
        _check_corpus_pass_selection_docs,
        _check_documentation_claims,
        _check_documentation_links,
        _check_pass_maturity_gap_summary,
        _check_readme_adversarial_summary,
        _check_readme_cross_platform_parity,
        _check_readme_differential_summary,
        _check_readme_pass_surface,
        _check_readme_support_summary,
        _check_readme_vm_resistance_summary,
        _check_readme_vm_review_scope,
        _check_release_blockers,
    )


try:
    from scripts.release_contract_artifacts import (
        _adversarial_release_signoff_blockers,
        _blocker_totals,
        _check_adversarial_benchmark_artifacts,
        _check_angr_runtime_available,
        _check_independent_review_artifact,
        _check_independent_review_packet_claims,
        _check_inventory,
        _check_vm_resistance_artifacts,
        _validate_adversarial_benchmark_artifact,
        _validate_adversarial_signoff_blockers,
        _validate_angr_runtime_available,
        _validate_bytecode_diversification,
        _validate_independent_review_artifact,
        _validate_independent_review_freshness,
        _validate_inventory,
        _validate_vm_resistance_artifacts,
    )
except ModuleNotFoundError:
    from release_contract_artifacts import (
        _check_adversarial_benchmark_artifacts,
        _check_angr_runtime_available,
        _check_independent_review_artifact,
        _check_independent_review_packet_claims,
        _check_inventory,
        _check_vm_resistance_artifacts,
    )


try:
    from scripts.release_contract_workflows import (
        _check_ci_contract,
        _check_corpus_workflows,
        _check_release_recovery_workflow,
        _check_release_workflow,
        _check_windows_download_contract,
    )
except ModuleNotFoundError:
    from release_contract_workflows import (
        _check_ci_contract,
        _check_corpus_workflows,
        _check_release_recovery_workflow,
        _check_release_workflow,
        _check_windows_download_contract,
    )

__all__ = (
    "ADVERSARIAL_TOOL_SLOTS",
    "FULL_EVIDENCE_PERCENT",
    "INDEPENDENT_REVIEW_CHECKS",
    "MAXIMUM_VM_HANDLER_SIMILARITY_ABOVE_THRESHOLD_PERCENT",
    "MINIMUM_COVERAGE_PERCENT",
    "MINIMUM_VM_VARIANT_COUNT",
    "PUBLIC_CLI_ALIASES",
    "REQUIRED_CI_JOBS",
    "REQUIRED_VM_TARGET_OPERATION",
    "REQUIRED_VM_TARGET_STRIDE_VALUES",
    "ROOT",
    "TIER_1_MATURITY_PROFILE",
    "VM_ADVERSARIAL_VALIDATION",
    "VM_HANDLER_COUNT",
    "VM_RESISTANCE_EVIDENCE_QUALITY",
    "VM_RESISTANCE_SEED_COUNT",
    "_BANNED_BINARY_NINJA_OMISSION_PHRASES",
    "_DOCUMENTATION_LINK_FILES",
    "_FORBIDDEN_RELEASE_CLAIMS",
    "_MARKDOWN_LINK_PATTERN",
    "_RELEASE_BLOCKER_FRAGMENTS",
    "_RELEASE_BLOCKER_IDS",
    "_RELEASE_BLOCKER_ID_PATTERN",
    "_RELEASE_BLOCKER_INDEX_AREAS",
    "_RELEASE_BLOCKER_REQUIRED_ENTRY_COUNT",
    "_RELEASE_HONESTY_FILES",
    "Path",
    "_adversarial_release_signoff_blockers",
    "_blocker_totals",
    "_check_adversarial_benchmark_artifacts",
    "_check_adversarial_benchmark_evidence",
    "_check_angr_runtime_available",
    "_check_changelog",
    "_check_ci_contract",
    "_check_corpus_pass_selection_docs",
    "_check_corpus_workflows",
    "_check_differential_gap_evidence",
    "_check_documentation_claims",
    "_check_documentation_links",
    "_check_independent_review_artifact",
    "_check_independent_review_packet_claims",
    "_check_inventory",
    "_check_matrix",
    "_check_maturity_gap_evidence",
    "_check_maturity_profile_values",
    "_check_one_zero_release_gate",
    "_check_parity_gap_evidence",
    "_check_pass_maturity_gap_summary",
    "_check_pass_selection_contract",
    "_check_readme_adversarial_summary",
    "_check_readme_cross_platform_parity",
    "_check_readme_differential_summary",
    "_check_readme_pass_surface",
    "_check_readme_support_summary",
    "_check_readme_vm_resistance_summary",
    "_check_readme_vm_review_scope",
    "_check_release_blockers",
    "_check_release_recovery_workflow",
    "_check_release_workflow",
    "_check_tier_1_maturity",
    "_check_version",
    "_check_vm_resistance_artifacts",
    "_check_vm_resistance_gap_evidence",
    "_check_vm_semantic_campaign",
    "_check_vm_semantic_campaign_capabilities",
    "_check_vm_semantic_fixture_coverage",
    "_check_vm_semantic_gap_evidence",
    "_check_windows_download_contract",
    "_forbidden_release_claims",
    "_load_matrix",
    "_validate_adversarial_benchmark_artifact",
    "_validate_adversarial_signoff_blockers",
    "_validate_angr_runtime_available",
    "_validate_bytecode_diversification",
    "_validate_independent_review_artifact",
    "_validate_independent_review_freshness",
    "_validate_inventory",
    "_validate_release_blockers_text",
    "_validate_vm_resistance_artifacts",
)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-current-human-signoff", action="store_true")
    args = parser.parse_args(arguments or [])
    try:
        package_version = _check_version()
        _check_one_zero_release_gate(
            package_version,
            ROOT / "docs" / "one-zero-readiness.json",
            ROOT,
        )
        matrix = _load_matrix()
        _check_matrix(matrix, package_version)
        _check_readme_support_summary(matrix)
        _check_readme_pass_surface(matrix)
        _check_readme_cross_platform_parity()
        _check_readme_differential_summary()
        _check_pass_maturity_gap_summary(matrix)
        _check_corpus_pass_selection_docs()
        _check_changelog(package_version)
        _check_inventory()
        _check_vm_resistance_artifacts()
        _check_independent_review_artifact(args.require_current_human_signoff)
        _check_independent_review_packet_claims()
        _check_adversarial_benchmark_artifacts()
        _check_angr_runtime_available()
        _check_readme_adversarial_summary()
        _check_readme_vm_review_scope()
        _check_readme_vm_resistance_summary()
        _check_documentation_links()
        _check_documentation_claims()
        _check_release_blockers()
        _check_ci_contract()
        _check_windows_download_contract()
        _check_release_workflow()
        _check_release_recovery_workflow()
        _check_corpus_workflows()
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"release contract failed: {exc}", file=sys.stderr)
        return 1
    print(f"release contract valid: {package_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
