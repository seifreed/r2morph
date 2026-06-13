"""Pass-outcome augmentation helpers for ValidationManager."""

from __future__ import annotations

from importlib import import_module
from typing import Any


def augment_pass_validation(
    binary: Any,
    pass_result: dict[str, Any],
    result: Any,
    symbolic_validator: Any,
    abi_validator: Any,
    symbolic_mode: bool,
    check_abi: bool,
) -> None:
    """Attach symbolic and ABI evidence to a pass-level validation outcome."""
    if symbolic_mode:
        _augment_symbolic_pass_validation(binary, pass_result, result, symbolic_validator)

    if check_abi:
        abi_issues = abi_validator.collect_violations(binary, pass_result)
        result.issues.extend(abi_issues)
        if abi_issues:
            result.passed = False
            result.metadata["abi_violations"] = len(abi_issues)


def _augment_symbolic_pass_validation(
    binary: Any,
    pass_result: dict[str, Any],
    result: Any,
    symbolic_validator: Any,
) -> None:
    """Mirror the symbolic metadata augmentation previously owned by ValidationManager."""
    result.metadata.update(symbolic_validator._run_symbolic_precheck(binary, pass_result))
    bridge_module = import_module("r2morph.analysis.symbolic.angr_bridge")
    if pass_result.get("pass_name") in {
        "InstructionSubstitution",
        "NopInsertion",
        "RegisterSubstitution",
    }:
        result.metadata.update(
            symbolic_validator._binary_comparator._compare_real_binary_regions(binary, pass_result, bridge_module)
        )
        if result.metadata.get("symbolic_binary_check_performed"):
            if result.metadata.get("symbolic_binary_equivalent"):
                result.metadata["symbolic_status"] = "real-binary-observables-match"
                result.metadata["symbolic_reason"] = (
                    "bounded real-binary symbolic effects matched for the mutated regions"
                )
            else:
                result.metadata["symbolic_status"] = "real-binary-observable-mismatch"
                result.metadata["symbolic_reason"] = (
                    "bounded real-binary symbolic effects diverged for the mutated regions"
                )
    symbolic_validator._mutation_annotator._annotate_mutations_with_symbolic_metadata(pass_result, result.metadata)
