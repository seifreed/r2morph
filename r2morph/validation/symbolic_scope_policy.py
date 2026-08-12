"""Pure policy helpers for the experimental symbolic-scope gate."""

from __future__ import annotations

from typing import Any

from r2morph.validation.address_parsing import parse_address

_MINIMUM_STEP_BUDGETS = {"RegisterSubstitution": 2, "NopInsertion": 2}
_SUPPORTED_BITS = 64
_MAX_MUTATIONS = 8
_MAX_MUTATION_SIZE_BYTES = 16
_SMALL_REGION_MAX_BYTES = 4
_MEDIUM_REGION_MAX_BYTES = 8


def build_scope_metadata(mutations: list[dict[str, Any]], pass_name: str) -> dict[str, Any]:
    """Build the symbolic-scope metadata block (independent of the verdict)."""
    return {
        "symbolic_backend": "angr",
        "symbolic_pass_name": pass_name,
        "covered_functions": sorted(
            {
                parse_address(mutation["function_address"])
                for mutation in mutations
                if mutation.get("function_address") not in (None, 0)
            }
        ),
        "covered_address_ranges": [
            [parse_address(mutation["start_address"]), parse_address(mutation["end_address"])] for mutation in mutations
        ],
    }


def check_scope_constraints(
    arch_info: dict[str, Any],
    mutations: list[dict[str, Any]],
    pass_name: str,
) -> tuple[bool, str] | None:
    """Return the (False, reason) rejection pair, or None when in scope."""
    binary_format = str(arch_info.get("format", ""))
    unsupported_target = (
        not binary_format.startswith("ELF")
        or arch_info.get("bits") != _SUPPORTED_BITS
        or arch_info.get("arch") not in {"x86", "x86_64"}
    )
    rejection = None
    if unsupported_target:
        rejection = (False, "unsupported-target")
    elif pass_name not in {"NopInsertion", "InstructionSubstitution", "RegisterSubstitution"}:
        rejection = (False, "unsupported-pass")
    elif not mutations:
        rejection = (False, "no-mutations")
    elif (
        len(mutations) > _MAX_MUTATIONS
        or any(
            (parse_address(mutation["end_address"]) - parse_address(mutation["start_address"]) + 1)
            > _MAX_MUTATION_SIZE_BYTES
            for mutation in mutations
        )
        or any(mutation.get("function_address") in (None, 0, "0x0") for mutation in mutations)
    ):
        rejection = (False, "unsupported-scope")
    return rejection


def estimate_symbolic_region_steps(pass_name: str, mutation: dict[str, Any]) -> int:
    """Estimate a small but useful symbolic step budget for a mutated region."""
    candidates: list[int] = []
    for key in ("original_disasm", "mutated_disasm"):
        disasm = mutation.get(key)
        if not disasm:
            continue
        if isinstance(disasm, str):
            instructions = [part.strip() for part in disasm.replace("\n", ";").split(";") if part.strip()]
            if instructions:
                candidates.append(len(instructions))

    region_size = parse_address(mutation.get("end_address", 0)) - parse_address(mutation.get("start_address", 0)) + 1
    if region_size > 0:
        candidates.append(
            1 if region_size <= _SMALL_REGION_MAX_BYTES else 2 if region_size <= _MEDIUM_REGION_MAX_BYTES else 3
        )

    step_budget = max(candidates or [1])
    step_budget = max(step_budget, _MINIMUM_STEP_BUDGETS.get(pass_name, 1))
    return max(1, min(step_budget, 4))
