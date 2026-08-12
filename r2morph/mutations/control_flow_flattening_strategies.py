"""Strategy helpers for control-flow flattening."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from r2morph.mutations.cff_jump_obfuscator import JumpObfuscator
from r2morph.mutations.cff_opaque_predicates import OpaquePredicateGenerator
from r2morph.mutations.control_flow_flattening_helpers import assemble_bounded
from r2morph.mutations.control_flow_flattening_helpers import (
    is_conditional_jump as _is_conditional_jump,
)
from r2morph.utils.dead_code import (
    generate_arm_dead_code_for_size,
    generate_nop_sequence,
    generate_x86_dead_code_for_size,
)

_MIN_PRECEDING_INSTRUCTION_COUNT = 2
_MIN_PREDICATE_SPACE_BYTES = 2


@dataclass(frozen=True)
class BlockStrategyContext:
    binary: Any
    arch_family: str
    bits: int
    mutations: dict[str, int]
    predicate_generator: OpaquePredicateGenerator
    jump_obfuscator: JumpObfuscator


def apply_block_strategies(
    context: BlockStrategyContext,
    blocks: list[Any],
    all_instrs: list[Any],
    predicates_to_add: int,
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

        if is_conditional_jump(mnemonic, context.arch_family) and try_add_opaque_predicate(
            context,
            block_instrs,
            last_addr,
        ):
            predicates_added += 1
            context.mutations["opaque_predicates"] += 1
            context.mutations["total"] += 1

        if (
            mnemonic == "jmp"
            and i < len(blocks) - 1
            and context.jump_obfuscator.obfuscate_jump(
                context.binary, last_insn, block, context.arch_family, context.bits
            )
        ):
            context.mutations["jump_obfuscations"] += 1
            context.mutations["total"] += 1

    return predicates_added


def try_add_opaque_predicate(
    context: BlockStrategyContext,
    block_instrs: list[Any],
    last_addr: int,
) -> bool:
    """Insert an opaque predicate into the slack space before a conditional jump."""
    if len(block_instrs) < _MIN_PRECEDING_INSTRUCTION_COUNT:
        return False

    prev_insn = block_instrs[-2]
    prev_addr = prev_insn.get("offset", 0)
    prev_size = prev_insn.get("size", 0)
    available_space = last_addr - (prev_addr + prev_size)

    if available_space < _MIN_PREDICATE_SPACE_BYTES:
        return False

    predicates = (
        context.predicate_generator.get_x86(context.bits)
        if context.arch_family == "x86"
        else context.predicate_generator.get_arm(context.bits)
    )
    return _write_opaque_predicate(
        context.binary,
        prev_addr + prev_size,
        available_space,
        (context.arch_family, context.bits),
        predicates,
    )


def add_opaque_predicate(
    binary: Any,
    addr: int,
    available_size: int,
    arch: str,
    bits: int,
) -> bool:
    """Add an opaque predicate at the specified address."""
    predicate_generator = OpaquePredicateGenerator()
    if arch == "x86":
        predicates = predicate_generator.get_x86(bits)
    elif arch == "arm":
        predicates = predicate_generator.get_arm(bits)
    else:
        return False
    return _write_opaque_predicate(binary, addr, available_size, (arch, bits), predicates)


def _write_opaque_predicate(
    binary: Any,
    addr: int,
    available_size: int,
    platform: tuple[str, int],
    predicates: list[list[str]],
) -> bool:
    arch, bits = platform
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


def is_conditional_jump(mnemonic: str, arch: str) -> bool:
    """Check if an instruction is a conditional jump/branch."""
    return _is_conditional_jump(mnemonic, arch)


__all__ = [
    "add_opaque_predicate",
    "apply_block_strategies",
    "insert_dead_code_with_predicate",
    "is_conditional_jump",
    "try_add_opaque_predicate",
]
