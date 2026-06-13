"""
Pattern Pool Registry for instruction pattern matching and mutation.

Provides a system for matching instruction patterns and generating
equivalent replacement code with weighted probabilities.
"""

import logging
import random
from typing import Any

from r2morph.mutations.pattern_generators import (
    generator_add_inc_chain,
    generator_add_to_lea,
    generator_and_reg_0,
    generator_dec_chain,
    generator_dec_to_sub,
    generator_inc_to_add,
    generator_mov_reg_0,
    generator_mov_reg_reg,
    generator_mov_with_junk_before,
    generator_push_pop_reg,
    generator_shl_to_lea,
    generator_sub_reg_same,
    generator_xor_reg_reg,
    generator_xor_with_junk,
)
from r2morph.mutations.pattern_rules import (
    match_add_reg_imm_small,
    match_and_reg_0_all,
    match_dec_reg,
    match_inc_reg,
    match_lea_reg_off,
    match_mov_reg_0_all,
    match_mov_reg_reg_reg64_reg16,
    match_push_pop_reg64_reg16,
    match_shl_reg_imm,
    match_sub_reg_imm_small,
    match_xor_reg_reg_all,
)
from r2morph.mutations.pattern_types import BasicBlock, Generator, Instruction, MatchRule

logger = logging.getLogger(__name__)


class MutationPatternPool:
    """
    Detects specific instruction patterns and replaces them with
    semantically equivalent alternatives.

    Each pattern pool contains:
    - match_rules: Functions that detect specific patterns
    - generators: Functions that produce replacement code (with weights)
    - mutation_probability: Chance to apply mutation (0-100%)
    """

    def __init__(
        self,
        name: str,
        match_rules: list[MatchRule],
        generators: list[tuple[Generator, int]],
        mutation_probability: int = 100,
    ):
        self.name = name
        self.match_rules = match_rules
        self.generators = generators
        self.mutation_probability = mutation_probability

    def match(self, block: BasicBlock, os_type: str = "linux", verbose: bool = False) -> BasicBlock:
        for rule in self.match_rules:
            matches = rule(block.instructions)

            for match in reversed(matches):
                if random.randint(0, 100) <= self.mutation_probability:
                    block = self._mutate(block, match.index, match.length, match.operands, os_type, verbose)

        return block

    def _mutate(
        self,
        block: BasicBlock,
        ins_idx: int,
        n_match_ins: int,
        operands: list[Any],
        os_type: str,
        verbose: bool,
    ) -> BasicBlock:
        generators_list, weights = zip(*self.generators)
        selected_generator = random.choices(generators_list, weights=weights, k=1)[0]

        new_instructions = selected_generator(operands, os_type)

        if verbose:
            self._log_mutation(
                block.instructions[ins_idx].address if ins_idx < len(block.instructions) else 0,
                block.instructions[ins_idx : ins_idx + n_match_ins],
                new_instructions,
            )

        block.instructions[ins_idx : ins_idx + n_match_ins] = new_instructions

        return block

    def _log_mutation(
        self,
        mutation_addr: int,
        old_instructions: list[Instruction],
        new_instructions: list[Instruction],
    ) -> None:
        old_opcodes = [ins.mnemonic if hasattr(ins, "mnemonic") else str(ins) for ins in old_instructions]
        new_opcodes = []

        for ins in new_instructions:
            if hasattr(ins, "mnemonic") and hasattr(ins, "operand_str"):
                new_opcodes.append([f"{ins.mnemonic} {ins.operand_str}"])
            elif hasattr(ins, "bytes"):
                hex_bytes = ins.bytes if isinstance(ins.bytes, str) else ins.bytes.hex()
                new_opcodes.append([hex_bytes[i : i + 35] for i in range(0, len(hex_bytes), 35)])
            else:
                new_opcodes.append([str(ins)])

        lines = [
            f"[v] mutation at {hex(mutation_addr)}:",
            f"{'old':<35} | {'new':<35}",
            "-" * 75,
        ]
        max_len = max(len(old_opcodes), len(new_opcodes))
        for i in range(max_len):
            old = old_opcodes[i] if i < len(old_opcodes) else ""
            new = new_opcodes[i] if i < len(new_opcodes) else [""]
            if i == 0 and old == "":
                old = "[insertion]"
            lines.append(f"{old:<35} | {new[0]:<35}")
            lines.extend(f"{'':<35} | {line:<35}" for line in new[1:])

        logger.debug("\n".join(lines))


_pattern_pool_registry: list[MutationPatternPool] = []


def register_pattern_pool(pool: MutationPatternPool) -> None:
    _pattern_pool_registry.append(pool)


def get_pattern_pools() -> list[MutationPatternPool]:
    return _pattern_pool_registry.copy()


def clear_pattern_pools() -> None:
    _pattern_pool_registry.clear()


and_reg_0_pool = MutationPatternPool(
    name="and_reg_0",
    match_rules=[match_and_reg_0_all],
    generators=[
        (generator_and_reg_0, 5),
        (generator_sub_reg_same, 5),
    ],
    mutation_probability=100,
)
register_pattern_pool(and_reg_0_pool)

inc_reg_pool = MutationPatternPool(
    name="inc_reg",
    match_rules=[match_inc_reg],
    generators=[
        (generator_inc_to_add, 5),
        (generator_add_to_lea, 2),
    ],
    mutation_probability=80,
)
register_pattern_pool(inc_reg_pool)

dec_reg_pool = MutationPatternPool(
    name="dec_reg",
    match_rules=[match_dec_reg],
    generators=[
        (generator_dec_to_sub, 5),
        (generator_dec_chain, 5),
    ],
    mutation_probability=80,
)
register_pattern_pool(dec_reg_pool)

shl_reg_pool = MutationPatternPool(
    name="shl_reg",
    match_rules=[match_shl_reg_imm],
    generators=[
        (generator_shl_to_lea, 3),
    ],
    mutation_probability=60,
)
register_pattern_pool(shl_reg_pool)

add_small_pool = MutationPatternPool(
    name="add_small",
    match_rules=[match_add_reg_imm_small],
    generators=[
        (generator_add_to_lea, 3),
        (generator_add_inc_chain, 2),
    ],
    mutation_probability=70,
)
register_pattern_pool(add_small_pool)

sub_small_pool = MutationPatternPool(
    name="sub_small",
    match_rules=[match_sub_reg_imm_small],
    generators=[
        (generator_dec_chain, 2),
    ],
    mutation_probability=70,
)
register_pattern_pool(sub_small_pool)

lea_off_pool = MutationPatternPool(
    name="lea_off",
    match_rules=[match_lea_reg_off],
    generators=[
        (generator_mov_reg_reg, 1),
    ],
    mutation_probability=50,
)
register_pattern_pool(lea_off_pool)

junk_enhanced_pool = MutationPatternPool(
    name="junk_enhanced",
    match_rules=[match_mov_reg_0_all, match_xor_reg_reg_all],
    generators=[
        (generator_xor_with_junk, 3),
        (generator_mov_with_junk_before, 3),
        (generator_mov_reg_0, 10),
        (generator_xor_reg_reg, 10),
    ],
    mutation_probability=30,
)
register_pattern_pool(junk_enhanced_pool)


mov_reg_value_pool = MutationPatternPool(
    name="mov_reg_value",
    match_rules=[match_mov_reg_reg_reg64_reg16, match_push_pop_reg64_reg16],
    generators=[
        (generator_mov_reg_reg, 1),
        (generator_push_pop_reg, 1),
    ],
    mutation_probability=100,
)
register_pattern_pool(mov_reg_value_pool)

set_reg_to_0_pool = MutationPatternPool(
    name="set_reg_to_0",
    match_rules=[match_mov_reg_0_all, match_xor_reg_reg_all],
    generators=[
        (generator_mov_reg_0, 10),
        (generator_xor_reg_reg, 10),
    ],
    mutation_probability=100,
)
register_pattern_pool(set_reg_to_0_pool)
