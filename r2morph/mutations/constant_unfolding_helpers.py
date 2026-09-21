"""Leaf helpers for constant unfolding candidate analysis and expansion."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.instruction_substitution_helpers import (
    flags_live_after,
    instruction_flags_written,
)

logger = logging.getLogger(__name__)

_BITS_64 = 64
_BITS_32 = 32
_ALTERNATE_ONE_PROBABILITY = 0.5
_MAX_UNIT_OPERATION_COUNT = 3
_MIN_INSTRUCTION_TOKEN_COUNT = 2
_ARM32_MOVW_MAXIMUM = 0xFFFF


def _is_arm64_register(register: str) -> bool:
    return register.startswith(("w", "x")) and register[1:].isdigit()


def _is_arm32_register(register: str, bits: int) -> bool:
    return bits == _BITS_32 and register.startswith("r") and register[1:].isdigit()


@dataclass(frozen=True, slots=True)
class UnfoldMutation:
    function_address: int
    address: int
    original_size: int
    original_disassembly: str
    instructions: tuple[str, ...]
    baseline: dict[str, Any]


def get_reg_mapping(bits: int) -> dict[str, list[str]]:
    """Get register mapping for architecture."""
    if bits == _BITS_64:
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
    if reg.startswith(("w", "x")) and reg[1:].isdigit():
        return [f"eor {reg}, {reg}, {reg}"]
    if bits == _BITS_32 and reg.startswith("r") and reg[1:].isdigit():
        return [f"eor {reg}, {reg}, {reg}"]
    patterns = [
        f"xor {reg}, {reg}",
        f"sub {reg}, {reg}",
        f"and {reg}, 0",
    ]
    return [random.choice(patterns)]


def unfold_one(reg: str, bits: int, binary: Any, base_addr: int) -> list[str] | None:
    """Unfold setting register to one."""
    if _is_arm64_register(reg):
        return [f"orr {reg}, wzr, 1"]
    if _is_arm32_register(reg, bits):
        return None
    if random.random() < _ALTERNATE_ONE_PROBABILITY:
        return [f"xor {reg}, {reg}", f"inc {reg}"]
    return [f"mov {reg}, 1"]


def unfold_constant_move(reg: str, value: int, bits: int, binary: Any, base_addr: int) -> list[str] | None:
    """Use a fixed-width ARM encoding for a materialized constant.

    AArch64 ``orr`` accepts only logical-immediate masks, so arbitrary values
    must use ``movz``. ARM32 uses ``movw`` when the target ISA supports it;
    both forms preserve flags and remain one instruction wide.
    """
    if _is_arm64_register(reg) and value not in (0, 1):
        logical_candidate = f"orr {reg}, wzr, {value}"
        if binary.assemble(logical_candidate, base_addr):
            return [logical_candidate]
        movz_candidate = f"movz {reg}, {value}"
        if binary.assemble(movz_candidate, base_addr):
            return [movz_candidate]
        return None
    if _is_arm32_register(reg, bits) and 0 <= value <= _ARM32_MOVW_MAXIMUM:
        candidate = f"movw {reg}, {value}"
        return [candidate] if binary.assemble(candidate, base_addr) else None
    return None


def _unfold_constant_step(reg: str, value: int, max_sequence: int, unit_op: str, bulk_op: str) -> list[str] | None:
    """Unfold a signed constant adjustment into unit (inc/dec) and bulk (add/sub) steps."""
    if value <= 0 or value > max_sequence:
        return None

    if value == 1:
        return [f"{unit_op} {reg}"]

    if value <= _MAX_UNIT_OPERATION_COUNT:
        return [f"{unit_op} {reg}"] * value

    half = value // 2
    remainder = value - half
    return [f"{bulk_op} {reg}, {half}", f"{bulk_op} {reg}, {remainder}"]


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
) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
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

        disasms = [insn.get("disasm", "").lower() for insn in instructions]
        candidates = []
        for index, insn in enumerate(instructions):
            disasm = insn.get("disasm", "").lower()
            mnemonic = disasm.split()[0] if disasm else ""

            if mnemonic not in ["mov", "movs", "add", "sub", "push", "xor"]:
                continue

            candidate = dict(insn)
            candidate["flags_live_after"] = flags_live_after(disasms, index)
            candidates.append(candidate)

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
    if len(parts) < _MIN_INSTRUCTION_TOKEN_COUNT:
        return None, False

    mnemonic = parts[0]
    reg = parts[1]
    value_str = parts[-1].lstrip("#") if len(parts) > _MIN_INSTRUCTION_TOKEN_COUNT else ""

    is_numeric = value_str.isdigit() or (
        value_str.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in value_str[2:])
    )
    if not is_numeric:
        return None, False

    value = int(value_str, 0)

    instructions = None
    if mnemonic in {"mov", "movs"} and value == 0:
        instructions = unfold_zero(reg, bits, binary, func_addr)
    elif mnemonic in {"mov", "movs"} and value == 1:
        instructions = unfold_one(reg, bits, binary, func_addr)
    elif mnemonic in {"mov", "movs"}:
        instructions = unfold_constant_move(reg, value, bits, binary, func_addr)
    elif (
        mnemonic == "add"
        and 1 < value <= max_sequence
        and not (_is_arm64_register(reg) or _is_arm32_register(reg, bits))
    ):
        instructions = unfold_constant_add(reg, value, bits, max_sequence)
    elif (
        mnemonic == "sub"
        and 1 < value <= max_sequence
        and not (_is_arm64_register(reg) or _is_arm32_register(reg, bits))
    ):
        instructions = unfold_constant_sub(reg, value, bits, max_sequence)
    return instructions, instructions is not None


def flags_preserved_for_unfold(original: str, unfolded: list[str], flags_live: bool) -> bool:
    """Reject an unfold whose final flags can differ while flags remain live."""
    if not flags_live:
        return True
    mnemonic = original.split(maxsplit=1)[0] if original else ""
    if mnemonic in {"add", "sub"}:
        return False
    original_flags = instruction_flags_written(original)
    unfolded_flags: frozenset[str] = frozenset()
    for instruction in unfolded:
        written = instruction_flags_written(instruction)
        if written:
            unfolded_flags = written
    return original_flags == unfolded_flags


def apply_single_unfold(
    pass_obj: Any,
    binary: Any,
    mutation: UnfoldMutation,
) -> bool:
    """Assemble, write, validate, and record a single unfold. Returns True on success."""
    addr = mutation.address
    orig_size = mutation.original_size
    all_bytes = b""
    for inst in mutation.instructions:
        inst_bytes = binary.assemble(inst, mutation.function_address)
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
        function_address=mutation.function_address,
        start_address=addr,
        end_address=addr + orig_size - 1,
        original_bytes=original_bytes,
        mutated_bytes=mutated_bytes,
        original_disasm=mutation.original_disassembly,
        mutated_disasm="; ".join(mutation.instructions),
        mutation_kind="constant_unfolding",
        metadata={
            "unfolded_instructions": len(mutation.instructions),
            "original_size": orig_size,
            "new_size": len(all_bytes),
            "structural_baseline": mutation.baseline,
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
    "UnfoldMutation",
    "apply_single_unfold",
    "calculate_sequence_size",
    "flags_preserved_for_unfold",
    "get_reg_mapping",
    "match_unfold_pattern",
    "select_candidates",
    "unfold_constant_add",
    "unfold_constant_move",
    "unfold_constant_sub",
    "unfold_one",
    "unfold_zero",
]
