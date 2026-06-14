"""Validation result assembly helpers."""

from __future__ import annotations

from typing import Any

from r2morph.validation.validator_execution_text import hash_text, normalize_output
from r2morph.validation.validator_runtime import RuntimeComparisonConfig, ValidationResult, ValidationTestCase


def calculate_similarity(
    original_outputs: list[dict[str, Any]],
    mutated_outputs: list[dict[str, Any]],
    comparison: RuntimeComparisonConfig,
) -> float:
    """Calculate similarity percentage between validation outputs."""
    if len(original_outputs) != len(mutated_outputs):
        return 0.0

    total_enabled_checks = 0
    total_matches = 0

    enabled_dimensions = []
    if comparison.compare_exitcode:
        enabled_dimensions.append("exitcode")
    if comparison.compare_stdout:
        enabled_dimensions.append("stdout")
    if comparison.compare_stderr:
        enabled_dimensions.append("stderr")
    if comparison.compare_files:
        enabled_dimensions.append("files")

    if not enabled_dimensions:
        return 100.0

    for orig, mut in zip(original_outputs, mutated_outputs, strict=False):
        total_enabled_checks += len(enabled_dimensions)

        if comparison.compare_exitcode and orig["exitcode"] == mut["exitcode"]:
            total_matches += 1
        if comparison.compare_stdout and orig["stdout"] == mut["stdout"]:
            total_matches += 1
        if comparison.compare_stderr and orig["stderr"] == mut["stderr"]:
            total_matches += 1
        if comparison.compare_files and orig.get("files", {}) == mut.get("files", {}):
            total_matches += 1

    return (total_matches / total_enabled_checks * 100) if total_enabled_checks > 0 else 0.0


def build_validation_result(
    *,
    all_outputs_match: bool,
    errors: list[str],
    original_outputs: list[dict[str, Any]],
    mutated_outputs: list[dict[str, Any]],
    comparison: RuntimeComparisonConfig,
    file_differences: dict[str, dict[str, str]],
    runtime_details: list[dict[str, Any]],
    test_cases: list[ValidationTestCase],
) -> ValidationResult:
    """Build a `ValidationResult` from collected runtime observations."""
    similarity = calculate_similarity(original_outputs, mutated_outputs, comparison)
    orig_combined = "\n".join(o["stdout"] for o in original_outputs)
    mut_combined = "\n".join(o["stdout"] for o in mutated_outputs)
    orig_exitcode = original_outputs[0]["exitcode"] if original_outputs else 0
    mut_exitcode = mutated_outputs[0]["exitcode"] if mutated_outputs else 0

    return ValidationResult(
        passed=all_outputs_match and len(errors) == 0,
        original_output=orig_combined,
        mutated_output=mut_combined,
        original_exitcode=orig_exitcode,
        mutated_exitcode=mut_exitcode,
        errors=errors,
        similarity_score=similarity,
        compared_signals={
            "exitcode": comparison.compare_exitcode,
            "stdout": comparison.compare_stdout,
            "stderr": comparison.compare_stderr,
            "files": comparison.compare_files,
            "normalize_whitespace": comparison.normalize_whitespace,
        },
        file_differences=file_differences,
        output_hashes={
            "original_stdout_sha256": hash_text(orig_combined),
            "mutated_stdout_sha256": hash_text(mut_combined),
            "original_stderr_sha256": hash_text("\n".join(o["stderr"] for o in original_outputs)),
            "mutated_stderr_sha256": hash_text("\n".join(o["stderr"] for o in mutated_outputs)),
            "normalized_original_stdout_sha256": hash_text(
                "\n".join(normalize_output(o["stdout"], comparison.normalize_whitespace) for o in original_outputs)
            ),
            "normalized_mutated_stdout_sha256": hash_text(
                "\n".join(normalize_output(o["stdout"], comparison.normalize_whitespace) for o in mutated_outputs)
            ),
        },
        runtime_details=runtime_details,
        test_cases=[case.to_dict() for case in test_cases],
    )
