"""Regression tests for pattern_integration verbose logging (§9).

The verbose mutation path used to print to stdout and additionally carried
a malformed f-string format spec that raised ``ValueError`` whenever
``verbose=True``. It now emits a single DEBUG log record instead.
"""

import logging

from r2morph.mutations.pattern_integration import PatternMatchIntegration
from r2morph.mutations.pattern_pool import (
    Instruction,
    MutationPatternPool,
    clear_pattern_pools,
    match_mov_reg_0_all,
    register_pattern_pool,
)


def _mov_zero_generator(operands, os_type):
    from r2morph.mutations.pattern_pool import _create_instruction

    return [_create_instruction("xor", [operands[0], operands[0]], "xor")]


def test_apply_patterns_verbose_logs_at_debug(caplog):
    clear_pattern_pools()
    register_pattern_pool(
        MutationPatternPool(
            name="movzero",
            match_rules=[match_mov_reg_0_all],
            generators=[(_mov_zero_generator, 10)],
            mutation_probability=100,
        )
    )
    try:
        integration = PatternMatchIntegration()
        instructions = [
            Instruction(address=0x1000, mnemonic="mov", operand_1="rax", operand_2="0", type="mov"),
            Instruction(address=0x1008, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov"),
        ]

        with caplog.at_level(logging.DEBUG, logger="r2morph.mutations.pattern_integration"):
            mutated, mutation_log = integration.apply_patterns_to_block(instructions, "linux", verbose=True)

        assert mutation_log, "expected at least one recorded mutation"
        assert any("Mutation at 0x1000" in record.message for record in caplog.records)
        assert mutated[0].mnemonic == "xor"
    finally:
        clear_pattern_pools()
