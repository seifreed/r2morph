"""Leaf helpers for constant unfolding candidate analysis and expansion."""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

logger = logging.getLogger(__name__)


def get_reg_mapping(bits: int) -> dict[str, list[str]]:
    """Get register mapping for architecture."""
    if bits == 64:
        return {
            "rax": ["rax", "eax", "r0"],
            "rbx": ["rbx", "ebx", "r3"],
            "rcx": ["rcx", "ecx", "r1"],
            "rdx": ["rdx", "edx", "r2"],
            "rsi": ["rsi", "esi"],
            "rdi": ["rdi", "edi"],
            "r8": ["r8", "r8d"],
            "r9": ["r9", "r9d"],
            "r10": ["r10", "r10d"],
            "r11": ["r11", "r11d"],
        }
    return {
        "eax": ["eax"],
        "ebx": ["ebx"],
        "ecx": ["ecx"],
        "edx": ["edx"],
        "esi": ["esi"],
        "edi": ["edi"],
    }


def unfold_zero(reg: str, bits: int, binary: Any, base_addr: int) -> list[str] | None:
    """Unfold setting register to zero."""
    patterns = [
        f"xor {reg}, {reg}",
        f"sub {reg}, {reg}",
        f"and {reg}, 0",
    ]
    return [random.choice(patterns)]


def unfold_one(reg: str, bits: int, binary: Any, base_addr: int) -> list[str] | None:
    """Unfold setting register to one."""
    if random.random() < 0.5:
        return [f"xor {reg}, {reg}", f"inc {reg}"]
    return [f"mov {reg}, 1"]


def _unfold_constant_step(reg: str, value: int, max_sequence: int, unit_op: str, bulk_op: str) -> list[str] | None:
    """Unfold a signed constant adjustment into unit (inc/dec) and bulk (add/sub) steps."""
    if value <= 0 or value > max_sequence:
        return None

    if value == 1:
        return [f"{unit_op} {reg}"]

    if value <= 3:
        return [f"{unit_op} {reg}"] * value

    half = value // 2
    remainder = value % 2

    result = [f"{bulk_op} {reg}, {half}"]
    if remainder:
        result.append(f"{unit_op} {reg}")
    return result


def unfold_constant_add(reg: str, value: int, bits: int, max_sequence: int) -> list[str] | None:
    """Unfold add reg, value into multiple operations."""
    return _unfold_constant_step(reg, value, max_sequence, "inc", "add")


def unfold_constant_sub(reg: str, value: int, bits: int, max_sequence: int) -> list[str] | None:
    """Unfold sub reg, value into multiple operations."""
    return _unfold_constant_step(reg, value, max_sequence, "dec", "sub")


def calculate_sequence_size(instructions: list[str], binary: Any, base_addr: int) -> int:
    """Calculate total size of instruction sequence."""
    total_size = 0
    for inst in instructions:
        if ";" in inst:
            parts = [p.strip() for p in inst.split(";")]
            for part in parts:
                bytes_result = binary.assemble(part, base_addr)
                total_size += len(bytes_result) if bytes_result else 0
        else:
            bytes_result = binary.assemble(inst, base_addr)
            total_size += len(bytes_result) if bytes_result else 0
    return total_size


def select_candidates(
    binary: Any,
    functions: list[dict[str, Any]],
    max_unfolds: int,
) -> list[tuple[dict, list]]:
    """Iterate functions, get disasm, and filter candidate instructions."""
    result = []
    for func in functions:
        if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
            continue

        try:
            instructions = binary.get_function_disasm(func["addr"])
        except Exception as e:
            logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
            continue

        candidates = []
        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            mnemonic = disasm.split()[0] if disasm else ""

            if mnemonic not in ["mov", "add", "sub", "push", "xor"]:
                continue

            candidates.append(insn)

        selected = random.sample(candidates, min(max_unfolds, len(candidates)))
        if selected:
            result.append((func, selected))
    return result


def match_unfold_pattern(
    disasm: str,
    bits: int,
    binary: Any,
    func_addr: int,
    max_sequence: int,
) -> tuple[list[str] | None, bool]:
    """Match instruction to an unfold pattern. Returns (unfolded_instructions, is_constant)."""
    parts = disasm.replace(",", " ").split()
    if len(parts) < 2:
        return None, False

    mnemonic = parts[0]
    reg = parts[1]
    value_str = parts[2] if len(parts) > 2 else ""

    is_numeric = value_str.isdigit() or (
        value_str.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in value_str[2:])
    )
    if not is_numeric:
        return None, False

    value = int(value_str, 0)

    if mnemonic == "mov" and value == 0:
        return unfold_zero(reg, bits, binary, func_addr), True
    if mnemonic == "mov" and value == 1:
        return unfold_one(reg, bits, binary, func_addr), True
    if mnemonic == "add" and 1 < value <= max_sequence:
        return unfold_constant_add(reg, value, bits, max_sequence), True
    if mnemonic == "sub" and 1 < value <= max_sequence:
        return unfold_constant_sub(reg, value, bits, max_sequence), True
    return None, False


def apply_single_unfold(
    pass_obj: Any,
    binary: Any,
    func: dict,
    addr: int,
    orig_size: int,
    disasm: str,
    unfolded: list[str],
    baseline: dict,
) -> bool:
    """Assemble, write, validate, and record a single unfold. Returns True on success."""
    all_bytes = b""
    for inst in unfolded:
        inst_bytes = binary.assemble(inst, func["addr"])
        if inst_bytes:
            all_bytes += inst_bytes

    if not all_bytes or len(all_bytes) > orig_size:
        return False

    original_bytes = binary.read_bytes(addr, orig_size)
    mutation_checkpoint = pass_obj._create_mutation_checkpoint("unfold")

    if not binary.write_bytes(addr, all_bytes):
        return False

    if len(all_bytes) < orig_size and not binary.nop_fill(addr + len(all_bytes), orig_size - len(all_bytes)):
        logger.warning("NOP fill failed at 0x%x after shorter unfold; rolling back", addr + len(all_bytes))
        if pass_obj._session is not None and mutation_checkpoint is not None:
            pass_obj._session.rollback_to(mutation_checkpoint)
        binary.reload()
        if pass_obj._rollback_policy == "fail-fast":
            raise RuntimeError("constant_unfolding NOP fill failed; aborting (fail-fast)")
        return False

    mutated_bytes = binary.read_bytes(addr, orig_size)
    record = pass_obj._record_mutation(
        function_address=func["addr"],
        start_address=addr,
        end_address=addr + orig_size - 1,
        original_bytes=original_bytes,
        mutated_bytes=mutated_bytes,
        original_disasm=disasm,
        mutated_disasm="; ".join(unfolded),
        mutation_kind="constant_unfolding",
        metadata={
            "unfolded_instructions": len(unfolded),
            "original_size": orig_size,
            "new_size": len(all_bytes),
            "structural_baseline": baseline,
        },
    )
    if pass_obj._validation_manager is not None:
        outcome = pass_obj._validation_manager.validate_mutation(binary, record.to_dict())
        if not outcome.passed and mutation_checkpoint is not None:
            if pass_obj._session is not None:
                pass_obj._session.rollback_to(mutation_checkpoint)
            binary.reload()
            if pass_obj._records:
                pass_obj._records.pop()
            if pass_obj._rollback_policy == "fail-fast":
                raise RuntimeError("Mutation-level validation failed")
            return False
    return True


__all__ = [
    "apply_single_unfold",
    "calculate_sequence_size",
    "get_reg_mapping",
    "match_unfold_pattern",
    "select_candidates",
    "unfold_constant_add",
    "unfold_constant_sub",
    "unfold_one",
    "unfold_zero",
]
