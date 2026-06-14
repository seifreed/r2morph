from __future__ import annotations

from collections.abc import Callable
from typing import Any

from r2morph.devirtualization.binary_rewriter_models import CodePatch


def validate_patches(
    patches: list[CodePatch],
    is_valid_address: Callable[[int], bool],
    validate_instructions: Callable[[list[str]], bool],
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    result: dict[str, Any] = {"valid": True, "errors": errors, "warnings": warnings}

    try:
        addresses = [patch.address for patch in patches]
        if len(addresses) != len(set(addresses)):
            errors.append("Overlapping patches detected")
            result["valid"] = False

        for i, patch in enumerate(patches):
            if not is_valid_address(patch.address):
                warnings.append(f"Patch {i}: Invalid address 0x{patch.address:x}")

            if patch.new_instructions and not validate_instructions(patch.new_instructions):
                warnings.append(f"Patch {i}: Invalid instructions")

            if abs(patch.size_change) > 1024:
                warnings.append(f"Patch {i}: Large size change ({patch.size_change} bytes)")

    except Exception as e:
        errors.append(f"Patch validation failed: {e}")
        result["valid"] = False

    return result


def plan_rewrite_strategy(patches: list[CodePatch]) -> dict[str, Any]:
    strategy: dict[str, Any] = {
        "use_code_caves": False,
        "expand_sections": False,
        "patch_order": [],
        "requires_relocation_update": False,
    }

    try:
        sorted_patches = sorted(patches, key=lambda p: p.address)
        strategy["patch_order"] = sorted_patches

        total_size_increase = sum(max(0, p.size_change) for p in patches)
        if total_size_increase > 100:
            strategy["use_code_caves"] = True

        if any(p.size_change != 0 for p in patches):
            strategy["requires_relocation_update"] = True

    except Exception as e:
        strategy["errors"] = [f"Strategy planning failed: {e}"]

    return strategy


def calculate_address_shifts(patches: list[CodePatch]) -> dict[int, int]:
    shifts: dict[int, int] = {}

    try:
        current_shift = 0
        for patch in sorted(patches, key=lambda p: p.address):
            shifts[patch.address] = current_shift
            current_shift += patch.size_change
    except Exception:
        return {}

    return shifts


def is_valid_address(sections: dict[str, Any], address: int) -> bool:
    try:
        for section in sections.values():
            start = section.get("vaddr", 0)
            size = section.get("vsize", 0)
            if start <= address < start + size:
                return True
        return False
    except (AttributeError, TypeError):
        return False


def validate_instructions(assembler: Any, instructions: list[str]) -> bool:
    try:
        if not assembler:
            return True

        asm_code = "; ".join(instructions)
        encoding, _ = assembler.asm(asm_code)
        return len(encoding) > 0
    except Exception:
        return False
