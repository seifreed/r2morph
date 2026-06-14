"""Pure policy helpers for the experimental symbolic-scope gate."""

from __future__ import annotations

from typing import Any

from r2morph.validation.address_parsing import parse_address


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
            [parse_address(mutation["start_address"]), parse_address(mutation["end_address"])]
            for mutation in mutations
        ],
    }


def check_scope_constraints(
    arch_info: dict[str, Any],
    mutations: list[dict[str, Any]],
    pass_name: str,
) -> tuple[bool, str] | None:
    """Return the (False, reason) rejection pair, or None when in scope."""
    binary_format = str(arch_info.get("format", ""))
    if not binary_format.startswith("ELF") or arch_info.get("bits") != 64:
        return False, "unsupported-target"
    if arch_info.get("arch") not in {"x86", "x86_64"}:
        return False, "unsupported-target"
    if pass_name not in {"NopInsertion", "InstructionSubstitution", "RegisterSubstitution"}:
        return False, "unsupported-pass"
    if not mutations:
        return False, "no-mutations"
    if len(mutations) > 8:
        return False, "unsupported-scope"
    if any((parse_address(mutation["end_address"]) - parse_address(mutation["start_address"]) + 1) > 16 for mutation in mutations):
        return False, "unsupported-scope"
    if any(mutation.get("function_address") in (None, 0, "0x0") for mutation in mutations):
        return False, "unsupported-scope"
    return None


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
        candidates.append(1 if region_size <= 4 else 2 if region_size <= 8 else 3)

    step_budget = max(candidates or [1])
    if pass_name == "RegisterSubstitution":
        step_budget = max(step_budget, 2)
    if pass_name == "NopInsertion":
        step_budget = max(step_budget, 2)
    return max(1, min(step_budget, 4))
