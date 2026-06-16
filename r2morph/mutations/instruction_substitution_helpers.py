"""Leaf helpers for instruction substitution equivalence matching."""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.equivalences import load_equivalence_rules

logger = logging.getLogger(__name__)


def init_substitution_rules() -> tuple[dict[str, list[list[str]]], dict[str, dict[str, int]]]:
    """Load and index substitution rules for all supported architectures."""
    equivalence_groups = {
        "x86": load_equivalence_rules("x86"),
        "arm": load_equivalence_rules("arm"),
        "arm64": load_equivalence_rules("arm64"),
    }

    for arch in equivalence_groups:
        for group in equivalence_groups[arch]:
            random.shuffle(group)

    pattern_to_group: dict[str, dict[str, int]] = {}
    for arch, groups in equivalence_groups.items():
        pattern_to_group.setdefault(arch, {})
        for group_idx, group in enumerate(groups):
            for pattern in group:
                normalized = normalize_instruction(pattern)
                pattern_to_group[arch][normalized] = group_idx

    return equivalence_groups, pattern_to_group


def normalize_instruction(disasm: str) -> str:
    """Normalize instruction text for pattern matching."""
    normalized = " ".join(disasm.lower().split())
    normalized = normalized.replace("0x0", "0")
    normalized = normalized.replace("0x1", "1")
    return normalized


# x86 status flags an instruction writes (AF omitted: set only by BCD ops and
# effectively never read). Two members of an equivalence group are flag-compatible
# when they write the same set; e.g. `xor`/`sub` both write {CF,ZF,SF,OF,PF} with
# the same values for a zeroed result, but `mov` writes nothing and `dec` leaves CF.
_ARITH_FLAGS = frozenset({"CF", "ZF", "SF", "OF", "PF"})
_NO_CARRY_FLAGS = frozenset({"ZF", "SF", "OF", "PF"})
_MULDIV_FLAGS = frozenset({"CF", "OF"})


def _build_flag_writes() -> dict[str, frozenset[str]]:
    arith = (
        "add",
        "sub",
        "cmp",
        "neg",
        "adc",
        "sbb",
        "and",
        "or",
        "xor",
        "test",
        "shl",
        "shr",
        "sal",
        "sar",
        "rol",
        "ror",
        "rcl",
        "rcr",
        "bt",
        "bts",
        "btr",
        "btc",
    )
    writes = {mnemonic: _ARITH_FLAGS for mnemonic in arith}
    writes.update({mnemonic: _NO_CARRY_FLAGS for mnemonic in ("inc", "dec")})
    writes.update({mnemonic: _MULDIV_FLAGS for mnemonic in ("mul", "imul", "div", "idiv")})
    return writes


_FLAG_WRITES = _build_flag_writes()
_FLAG_READING_MNEMONICS = frozenset({"adc", "sbb", "rcl", "rcr", "sahf", "lahf", "into", "pushf", "pushfd", "pushfq"})
_FLAG_NEUTRAL_TERMINATORS = frozenset({"ret", "retn", "call", "syscall", "sysenter", "int", "hlt"})


def instruction_flags_written(disasm: str) -> frozenset[str]:
    """x86 status flags an instruction writes (empty for flag-neutral ops)."""
    tokens = disasm.lower().split()
    return _FLAG_WRITES.get(tokens[0], frozenset()) if tokens else frozenset()


def equivalent_flags_written(equivalent: str) -> frozenset[str]:
    """Net flags left by an equivalent (the last sub-instruction that writes any)."""
    net: frozenset[str] = frozenset()
    for part in equivalent.split(";"):
        written = instruction_flags_written(part.strip())
        if written:
            net = written
    return net


def _reads_flags(disasm: str) -> bool:
    tokens = disasm.lower().split()
    if not tokens:
        return False
    mnemonic = tokens[0]
    if mnemonic in _FLAG_READING_MNEMONICS:
        return True
    if mnemonic.startswith(("set", "cmov")):
        return True
    if mnemonic.startswith("j") and mnemonic != "jmp":  # conditional jumps
        return True
    return mnemonic in ("loope", "loopne", "loopz", "loopnz")


def flags_live_after(disasms: list[str], index: int) -> bool:
    """True if a status flag may be read before being overwritten after ``index``.

    Conservative at control flow: an unconditional jump leaves the target unknown
    (assumed live); a return or call ends/clobbers the flags (assumed dead)."""
    for following in disasms[index + 1 :]:
        if _reads_flags(following):
            return True
        if instruction_flags_written(following):
            return False
        tokens = following.split()
        mnemonic = tokens[0] if tokens else ""
        if mnemonic in _FLAG_NEUTRAL_TERMINATORS:
            return False
        if mnemonic == "jmp" or mnemonic.startswith(("j", "loop")):
            return True
    return False


def flags_live_at(instructions: list[dict[str, Any]], insert_addr: int, arch: str) -> bool:
    """True if inserting flag-clobbering code at ``insert_addr`` could corrupt flow.

    Returns True when an x86 status flag may be read after ``insert_addr`` before
    being overwritten, so a flag-clobbering insertion there would break a
    downstream conditional. Conservatively True for non-x86 architectures, where
    there is no flag model yet, so flag-clobbering code is never inserted there.

    ``instructions`` are radare2 disassembly records (address under ``addr``,
    text under ``disasm``/``opcode``) in ascending address order.
    """
    if arch != "x86":
        return True
    disasms = [ins.get("disasm", ins.get("opcode", "")) for ins in instructions]
    idx = -1
    for j, ins in enumerate(instructions):
        if ins.get("addr", ins.get("offset", 0)) < insert_addr:
            idx = j
        else:
            break
    return flags_live_after(disasms, idx)


def get_equivalents(
    instruction: dict[str, Any],
    arch: str,
    pattern_to_group: dict[str, dict[str, int]],
    equivalence_groups: dict[str, list[list[str]]],
) -> tuple[str, list[str], int | None]:
    """Return the equivalence group for an instruction if one exists."""
    if arch not in pattern_to_group:
        return ("", [], None)

    disasm = instruction.get("disasm", "")
    normalized = normalize_instruction(disasm)

    if normalized in pattern_to_group[arch]:
        group_idx = pattern_to_group[arch][normalized]
        equivalents = equivalence_groups[arch][group_idx]
        return (normalized, equivalents, group_idx)

    return ("", [], None)


def select_candidates(
    binary: Any,
    functions: list[dict[str, Any]],
    arch_family: str,
    pattern_to_group: dict[str, dict[str, int]],
    equivalence_groups: dict[str, list[list[str]]],
) -> list[tuple[dict, list]]:
    """Select functions that contain substitution candidates."""
    result = []
    for func in functions:
        if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
            continue

        try:
            func_addr = func.get("offset", func.get("addr", 0))
            instructions = binary.get_function_disasm(func_addr)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
            continue

        disasms = [insn.get("disasm", "").lower() for insn in instructions]
        candidates = []
        for index, insn in enumerate(instructions):
            original_pattern, equivalents, group_idx = get_equivalents(
                insn, arch_family, pattern_to_group, equivalence_groups
            )
            if equivalents and len(equivalents) > 1:
                insn["flags_live_after"] = flags_live_after(disasms, index)
                candidates.append(insn)
        if candidates:
            result.append((func, candidates))
    return result


__all__ = [
    "equivalent_flags_written",
    "flags_live_after",
    "flags_live_at",
    "get_equivalents",
    "init_substitution_rules",
    "instruction_flags_written",
    "normalize_instruction",
    "select_candidates",
]
