"""Strategy helpers for control-flow flattening."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.cff_jump_obfuscator import JumpObfuscator
from r2morph.mutations.cff_opaque_predicates import OpaquePredicateGenerator
from r2morph.utils.dead_code import (
    generate_arm_dead_code_for_size,
    generate_nop_sequence,
    generate_x86_dead_code_for_size,
)


def apply_block_strategies(
    binary: Any,
    blocks: list[Any],
    all_instrs: list[Any],
    arch_family: str,
    bits: int,
    predicates_to_add: int,
    mutations: dict[str, int],
    predicate_generator: OpaquePredicateGenerator,
    jump_obfuscator: JumpObfuscator,
) -> int:
    """Apply per-block opaque-predicate and jump-obfuscation strategies."""
    predicates_added = 0
    for i, block in enumerate(blocks):
        if predicates_added >= predicates_to_add:
            break

        block_addr = block.get("addr", 0)
        block_size = block.get("size", 0)
        block_end = block_addr + block_size
        block_instrs = [ins for ins in all_instrs if block_addr <= ins.get("offset", 0) < block_end]
        if not block_instrs:
            continue

        last_insn = block_instrs[-1]
        last_addr = last_insn.get("offset", 0)
        mnemonic = last_insn.get("mnemonic", "").lower()

        if is_conditional_jump(mnemonic, arch_family) and try_add_opaque_predicate(
            binary,
            block_instrs,
            last_addr,
            arch_family,
            bits,
            predicate_generator,
        ):
            predicates_added += 1
            mutations["opaque_predicates"] += 1
            mutations["total"] += 1

        if mnemonic == "jmp" and i < len(blocks) - 1:
            if jump_obfuscator.obfuscate_jump(binary, last_insn, block, arch_family, bits):
                mutations["jump_obfuscations"] += 1
                mutations["total"] += 1

    return predicates_added


def try_add_opaque_predicate(
    binary: Any,
    block_instrs: list[Any],
    last_addr: int,
    arch_family: str,
    bits: int,
    predicate_generator: OpaquePredicateGenerator,
) -> bool:
    """Insert an opaque predicate into the slack space before a conditional jump."""
    if len(block_instrs) < 2:
        return False

    prev_insn = block_instrs[-2]
    prev_addr = prev_insn.get("offset", 0)
    prev_size = prev_insn.get("size", 0)
    available_space = last_addr - (prev_addr + prev_size)

    if available_space < 2:
        return False

    if not add_opaque_predicate(binary, prev_addr + prev_size, available_space, arch_family, bits, predicate_generator):
        return False

    return True


def add_opaque_predicate(
    binary: Any,
    addr: int,
    available_size: int,
    arch: str,
    bits: int,
    predicate_generator: OpaquePredicateGenerator,
) -> bool:
    """Add an opaque predicate at the specified address."""
    if arch == "x86":
        predicates = predicate_generator.get_x86(bits)
    elif arch == "arm":
        predicates = predicate_generator.get_arm(bits)
    else:
        return False

    for predicate_insns in predicates:
        assembled = assemble_bounded(binary, predicate_insns, available_size)
        if assembled is None:
            continue

        if len(assembled) < available_size:
            assembled += generate_nop_sequence(arch, bits, available_size - len(assembled))

        return bool(binary.write_bytes(addr, assembled))

    return False


def insert_dead_code_with_predicate(binary: Any, addr: int, size: int, arch: str, bits: int) -> bool:
    """Insert dead code containing an opaque predicate into a NOP sled."""
    if arch == "x86":
        dead_code = generate_x86_dead_code_for_size(size, bits)
    elif arch == "arm":
        dead_code = generate_arm_dead_code_for_size(size, bits)
    else:
        return False

    assembled = assemble_bounded(binary, dead_code, size)
    if not assembled:
        return False

    if len(assembled) < size:
        assembled += generate_nop_sequence(arch, bits, size - len(assembled))

    return bool(binary.write_bytes(addr, assembled))


def assemble_bounded(binary: Any, instructions: list[str], max_size: int) -> bytes | None:
    """Assemble ``instructions``; return None if any fails or exceeds size."""
    assembled = b""
    for insn in instructions:
        insn_bytes = binary.assemble(insn)
        if insn_bytes is None:
            return None
        assembled += insn_bytes
        if len(assembled) > max_size:
            return None
    return assembled


def is_conditional_jump(mnemonic: str, arch: str) -> bool:
    """Check if an instruction is a conditional jump/branch."""
    from r2morph.mutations.control_flow_flattening_helpers import is_conditional_jump as _is_conditional_jump

    return _is_conditional_jump(mnemonic, arch)


__all__ = [
    "add_opaque_predicate",
    "apply_block_strategies",
    "assemble_bounded",
    "insert_dead_code_with_predicate",
    "is_conditional_jump",
    "try_add_opaque_predicate",
]
