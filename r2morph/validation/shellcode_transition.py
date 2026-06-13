"""Transition comparison helpers for shellcode equivalence."""

from __future__ import annotations

from importlib import import_module
from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.shellcode_equivalence_common import load_shellcode_state_pair, record_mismatch


def compare_instruction_substitution_transition(
    binary: Binary,
    pass_result: dict[str, Any],
    bridge_module: Any,
) -> dict[str, Any]:
    """Compare successor address and stack delta for supported substitution snippets."""
    angr_module = getattr(bridge_module, "angr", None)
    if angr_module is None:
        return {
            "symbolic_transition_check_performed": False,
            "symbolic_transition_reason": "angr module not available",
        }

    config = _transition_arch_config(binary.get_arch_info())
    if config is None:
        return {
            "symbolic_transition_check_performed": False,
            "symbolic_transition_reason": "unsupported architecture for transition check",
        }
    shellcode_arch, stack_reg, bit_width = config

    options = angr_module.options
    claripy = import_module("claripy")
    compared_regions: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []

    try:
        for mutation in pass_result.get("mutations", []):
            metadata = mutation.get("metadata", {})
            if not isinstance(metadata.get("equivalence_group_index"), int):
                continue
            region_report, region_mismatches = _compare_transition_region(
                angr_module, claripy, options, mutation, shellcode_arch, stack_reg, bit_width
            )
            compared_regions.append(region_report)
            mismatches.extend(region_mismatches)
    except Exception as e:  # angr symbolic execution may raise any exception type
        return {
            "symbolic_transition_check_performed": False,
            "symbolic_transition_reason": f"transition check failed: {e}",
        }

    return _build_transition_result(compared_regions, mismatches)


def _transition_arch_config(arch_info: dict[str, Any]) -> tuple[str, str, int] | None:
    """Return (shellcode_arch, stack_reg, bit_width) or None when unsupported."""
    arch = arch_info.get("arch")
    bits = arch_info.get("bits")
    if arch in {"x86", "x86_64"} and bits == 64:
        return "amd64", "rsp", 64
    if arch == "x86" and bits == 32:
        return "x86", "esp", 32
    return None


def _compare_transition_region(
    angr_module: Any,
    claripy: Any,
    options: Any,
    mutation: dict[str, Any],
    shellcode_arch: str,
    stack_reg: str,
    bit_width: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Compare successor address + stack delta for one substitution region."""
    original_project, original_state, mutated_project, mutated_state = load_shellcode_state_pair(
        angr_module, options, mutation, shellcode_arch
    )
    shared_stack = claripy.BVV(0x100000, bit_width)
    setattr(original_state.regs, stack_reg, shared_stack)
    setattr(mutated_state.regs, stack_reg, shared_stack)

    original_succ = list(original_project.factory.successors(original_state).flat_successors)
    mutated_succ = list(mutated_project.factory.successors(mutated_state).flat_successors)
    region_report: dict[str, Any] = {
        "start_address": mutation["start_address"],
        "end_address": mutation["end_address"],
        "original_successors": len(original_succ),
        "mutated_successors": len(mutated_succ),
        "mismatches": [],
    }
    region_mismatches: list[dict[str, Any]] = []

    if len(original_succ) != 1 or len(mutated_succ) != 1:
        record_mismatch(region_report, region_mismatches, mutation, "successor_count")
        return region_report, region_mismatches

    original_final = original_succ[0]
    mutated_final = mutated_succ[0]
    if getattr(original_final, "addr", None) != getattr(mutated_final, "addr", None):
        record_mismatch(region_report, region_mismatches, mutation, "successor_address")

    original_stack = getattr(original_final.regs, stack_reg)
    mutated_stack = getattr(mutated_final.regs, stack_reg)
    if original_final.solver.satisfiable(extra_constraints=[original_stack != mutated_stack]):
        record_mismatch(region_report, region_mismatches, mutation, "stack_delta")
    return region_report, region_mismatches


def _build_transition_result(
    compared_regions: list[dict[str, Any]],
    mismatches: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assemble the transition-check result dict from the per-region outcomes."""
    return {
        "symbolic_transition_check_performed": bool(compared_regions),
        "symbolic_transition_equivalent": not mismatches if compared_regions else False,
        "symbolic_transition_reason": (
            "successor address and stack delta matched"
            if compared_regions and not mismatches
            else (
                "transition differences detected"
                if compared_regions
                else "no eligible instruction substitutions for transition check"
            )
        ),
        "symbolic_transition_regions": compared_regions,
        "symbolic_transition_mismatches": mismatches,
    }
