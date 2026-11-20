from __future__ import annotations

from collections.abc import Callable
from typing import Any

from r2morph.devirtualization.binary_rewriter_models import CodePatch, RewriteOperation

_MAX_PATCH_SIZE_CHANGE_BYTES = 1024
_CODE_CAVE_SIZE_INCREASE_THRESHOLD_BYTES = 100


def validate_patches(
    patches: list[CodePatch],
    is_valid_address: Callable[[int], bool],
    validate_instructions: Callable[[list[str]], bool],
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    result: dict[str, Any] = {"valid": True, "errors": errors, "warnings": warnings}

    try:
        ordered = sorted(patches, key=lambda patch: patch.address)
        previous_end: int | None = None
        previous_start: int | None = None
        for i, patch in enumerate(patches):
            if not is_valid_address(patch.address):
                errors.append(f"Patch {i}: Invalid address 0x{patch.address:x}")

            if patch.new_instructions and not validate_instructions(patch.new_instructions):
                errors.append(f"Patch {i}: Invalid instructions")

            if patch.operation != RewriteOperation.INSTRUCTION_REPLACE:
                errors.append(f"Patch {i}: Unsupported operation {patch.operation.value}")

            if patch.size_change != len(patch.new_bytes) - len(patch.original_bytes):
                errors.append(f"Patch {i}: Size change does not match byte lengths")

            if not patch.original_bytes or len(patch.original_bytes) != len(patch.new_bytes):
                errors.append(f"Patch {i}: Only non-empty size-preserving replacements are supported")

        for i, patch in enumerate(ordered):
            if abs(patch.size_change) > _MAX_PATCH_SIZE_CHANGE_BYTES:
                warnings.append(f"Patch {i}: Large size change ({patch.size_change} bytes)")
            if previous_end is not None and (patch.address < previous_end or patch.address == previous_start):
                errors.append("Overlapping patches detected")
                break
            previous_start = patch.address
            previous_end = patch.address + len(patch.original_bytes)

        result["valid"] = not errors

    except Exception as e:
        errors.append(f"Patch validation failed: {e}")
        result["valid"] = False

    return result


def apply_patch_to_buffer(buffer: bytearray, offset: int, patch: CodePatch) -> bool:
    """Apply a size-preserving replacement only when its source bytes still match."""
    end = offset + len(patch.original_bytes)
    if (
        patch.operation != RewriteOperation.INSTRUCTION_REPLACE
        or patch.size_change != 0
        or not patch.original_bytes
        or len(patch.original_bytes) != len(patch.new_bytes)
        or offset < 0
        or end > len(buffer)
        or buffer[offset:end] != patch.original_bytes
    ):
        return False
    buffer[offset:end] = patch.new_bytes
    return True


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
        if total_size_increase > _CODE_CAVE_SIZE_INCREASE_THRESHOLD_BYTES:
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
