"""Artifact assembly helpers for validation results."""

from __future__ import annotations

from typing import Any

from r2morph.validation.validator_execution_text import hash_text, normalize_output
from r2morph.validation.validator_runtime import RuntimeComparisonConfig


def build_compared_signals(comparison: RuntimeComparisonConfig) -> dict[str, bool]:
    """Build the compared-signals payload."""
    return {
        "exitcode": comparison.compare_exitcode,
        "stdout": comparison.compare_stdout,
        "stderr": comparison.compare_stderr,
        "files": comparison.compare_files,
        "normalize_whitespace": comparison.normalize_whitespace,
    }


def build_output_hashes(
    original_outputs: list[dict[str, Any]],
    mutated_outputs: list[dict[str, Any]],
    comparison: RuntimeComparisonConfig,
) -> dict[str, str]:
    """Build stable hashes for validation output artefacts."""
    orig_combined = "\n".join(o["stdout"] for o in original_outputs)
    mut_combined = "\n".join(o["stdout"] for o in mutated_outputs)
    return {
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
    }
