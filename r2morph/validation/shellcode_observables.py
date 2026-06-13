"""Observable comparison helpers for shellcode equivalence."""

from __future__ import annotations

from importlib import import_module
from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.shellcode_equivalence_common import load_shellcode_state_pair, record_mismatch


def compare_instruction_substitution_observables(
    binary: Binary,
    pass_result: dict[str, Any],
    bridge_module: Any,
) -> dict[str, Any]:
    """Compare a small set of observable register/flag effects for InstructionSubstitution snippets."""
    angr_module = getattr(bridge_module, "angr", None)
    if angr_module is None:
        return {
            "symbolic_observable_check_performed": False,
            "symbolic_observable_reason": "angr module not available",
        }

    config = _observables_arch_config(binary.get_arch_info())
    if config is None:
        return {
            "symbolic_observable_check_performed": False,
            "symbolic_observable_reason": "unsupported architecture for observable check",
        }
    shellcode_arch, observables = config

    options = angr_module.options
    claripy = import_module("claripy")
    compared_regions: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []

    try:
        for mutation in pass_result.get("mutations", []):
            metadata = mutation.get("metadata", {})
            if not isinstance(metadata.get("equivalence_group_index"), int):
                continue
            region_report, region_mismatches = _compare_observable_region(
                angr_module,
                claripy,
                options,
                mutation,
                shellcode_arch,
                observables,
            )
            compared_regions.append(region_report)
            mismatches.extend(region_mismatches)
    except Exception as e:  # angr symbolic execution may raise any exception type
        return {
            "symbolic_observable_check_performed": False,
            "symbolic_observable_reason": f"observable check failed: {e}",
        }

    return _build_observable_result(compared_regions, mismatches)


def _observables_arch_config(arch_info: dict[str, Any]) -> tuple[str, list[str]] | None:
    """Return (shellcode_arch, observables) or None when unsupported."""
    arch = arch_info.get("arch")
    bits = arch_info.get("bits")
    if arch in {"x86", "x86_64"} and bits == 64:
        return "amd64", ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "eflags"]
    if arch == "x86" and bits == 32:
        return "x86", ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eflags"]
    return None


def _seed_observable_registers(
    claripy: Any,
    original_state: Any,
    mutated_state: Any,
    mutation: dict[str, Any],
    shellcode_arch: str,
    observables: list[str],
) -> None:
    """Pin the stack/base pointers and share symbolic values for the tracked registers."""
    bit_width = 64 if shellcode_arch == "amd64" else 32
    stack_reg = "rsp" if shellcode_arch == "amd64" else "esp"
    base_reg = "rbp" if shellcode_arch == "amd64" else "ebp"
    setattr(original_state.regs, stack_reg, claripy.BVV(0x100000, bit_width))
    setattr(mutated_state.regs, stack_reg, claripy.BVV(0x100000, bit_width))
    setattr(original_state.regs, base_reg, claripy.BVV(0x100000, bit_width))
    setattr(mutated_state.regs, base_reg, claripy.BVV(0x100000, bit_width))

    for reg_name in observables:
        if reg_name in {stack_reg, base_reg, "eflags"}:
            continue
        shared = claripy.BVS(
            f"{reg_name}_{mutation['start_address']:x}",
            64 if reg_name.startswith("r") else 32,
        )
        if hasattr(original_state.regs, reg_name):
            setattr(original_state.regs, reg_name, shared)
        if hasattr(mutated_state.regs, reg_name):
            setattr(mutated_state.regs, reg_name, shared)


def _compare_observable_region(
    angr_module: Any,
    claripy: Any,
    options: Any,
    mutation: dict[str, Any],
    shellcode_arch: str,
    observables: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Compare observable register/flag effects for one substitution region."""
    original_project, original_state, mutated_project, mutated_state = load_shellcode_state_pair(
        angr_module, options, mutation, shellcode_arch
    )
    _seed_observable_registers(claripy, original_state, mutated_state, mutation, shellcode_arch, observables)

    original_succ = list(original_project.factory.successors(original_state).flat_successors)
    mutated_succ = list(mutated_project.factory.successors(mutated_state).flat_successors)
    region_report: dict[str, Any] = {
        "start_address": mutation["start_address"],
        "end_address": mutation["end_address"],
        "observables_checked": list(observables),
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

    for observable in observables:
        if not hasattr(original_final.regs, observable) or not hasattr(mutated_final.regs, observable):
            continue
        left = getattr(original_final.regs, observable)
        right = getattr(mutated_final.regs, observable)
        if original_final.solver.satisfiable(extra_constraints=[left != right]):
            record_mismatch(region_report, region_mismatches, mutation, observable)
    return region_report, region_mismatches


def _build_observable_result(
    compared_regions: list[dict[str, Any]],
    mismatches: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assemble the observable-check result dict from the per-region outcomes."""
    return {
        "symbolic_observable_check_performed": bool(compared_regions),
        "symbolic_observable_equivalent": not mismatches if compared_regions else False,
        "symbolic_observable_reason": (
            "observable register/flag effects matched"
            if compared_regions and not mismatches
            else (
                "observable register/flag differences detected"
                if compared_regions
                else "no eligible instruction substitutions for observable check"
            )
        ),
        "symbolic_observable_regions": compared_regions,
        "symbolic_observable_mismatches": mismatches,
    }
