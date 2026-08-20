"""
Tests for pattern_pool module.
"""

import importlib
import logging

from r2morph.mutations.pattern_generators import _create_instruction
from r2morph.mutations.pattern_pool import (
    MutationPatternPool,
    clear_pattern_pools,
    get_pattern_pools,
    register_pattern_pool,
)
from r2morph.mutations.pattern_rules import (
    match_add_reg_imm_small,
    match_and_reg_0_all,
    match_dec_reg,
    match_inc_reg,
    match_mov_reg_0_all,
    match_shl_reg_imm,
    match_xor_reg_reg_all,
)
from r2morph.mutations.pattern_types import BasicBlock, Instruction, MatchResult
from tests.utils.assertions import expect

_EXPECTED_LEN_MUTATED_BLOCK_INSTRUCTIONS_2 = 2
_EXPECTED_LEN_POOLS_2 = 2
_EXPECTED_RESULT_INDEX_5 = 5
_EXPECTED_RESULT_LENGTH_2 = 2


class TestInstruction:
    def test_create_instruction_basic(self):
        ins = _create_instruction("mov", ["rax", "rbx"], "mov")
        expect(ins.mnemonic == "mov")
        expect(ins.operand_1 == "rax")
        expect(ins.operand_2 == "rbx")
        expect(ins.operand_str == "rax, rbx")
        expect(ins.type == "mov")
        expect(not (ins.mutated is not True))

    def test_create_instruction_single_operand(self):
        ins = _create_instruction("inc", ["rax"], "inc")
        expect(ins.mnemonic == "inc")
        expect(ins.operand_1 == "rax")
        expect(ins.operand_2 == "")

    def test_create_instruction_no_type(self):
        ins = _create_instruction("push", ["rbx"])
        expect(ins.mnemonic == "push")
        expect(ins.type == "push")


class TestMatchRules:
    def test_match_mov_reg_0_single_reg(self):
        ins1 = Instruction(address=0x1000, mnemonic="mov", operand_1="rax", operand_2="0", type="mov")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        matches = match_mov_reg_0_all([ins1, ins2])
        expect(len(matches) == 1)
        expect(matches[0].operands[0] == "rax")

    def test_match_mov_reg_0_excludes_cjmp(self):
        ins1 = Instruction(address=0x1000, mnemonic="mov", operand_1="rax", operand_2="0", type="mov")
        ins2 = Instruction(address=0x1005, mnemonic="jz", operand_1="0x2000", type="cjmp")
        matches = match_mov_reg_0_all([ins1, ins2])
        expect(len(matches) == 0)

    def test_match_xor_reg_reg(self):
        ins1 = Instruction(address=0x1000, mnemonic="xor", operand_1="rax", operand_2="rax", type="xor")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        matches = match_xor_reg_reg_all([ins1, ins2])
        expect(len(matches) == 1)

    def test_match_xor_reg_reg_different_regs(self):
        ins1 = Instruction(address=0x1000, mnemonic="xor", operand_1="rax", operand_2="rbx", type="xor")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        matches = match_xor_reg_reg_all([ins1, ins2])
        expect(len(matches) == 0)

    def test_match_and_reg_0(self):
        ins1 = Instruction(address=0x1000, mnemonic="and", operand_1="rax", operand_2="0", type="and")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        matches = match_and_reg_0_all([ins1, ins2])
        expect(len(matches) == 1)

    def test_match_inc_reg(self):
        ins1 = Instruction(address=0x1000, mnemonic="inc", operand_1="rax", type="inc")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        matches = match_inc_reg([ins1, ins2])
        expect(len(matches) == 1)

    def test_match_dec_reg(self):
        ins1 = Instruction(address=0x1000, mnemonic="dec", operand_1="rax", type="dec")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        matches = match_dec_reg([ins1, ins2])
        expect(len(matches) == 1)

    def test_match_shl_reg_imm(self):
        ins1 = Instruction(address=0x1000, mnemonic="shl", operand_1="rax", operand_2="2", type="shl")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        matches = match_shl_reg_imm([ins1, ins2])
        expect(len(matches) == 1)

    def test_match_add_reg_imm_small(self):
        ins1 = Instruction(address=0x1000, mnemonic="add", operand_1="rax", operand_2="5", type="add")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        matches = match_add_reg_imm_small([ins1, ins2])
        expect(len(matches) == 1)


class TestMutationPatternPool:
    def test_pool_creation(self):
        pool = MutationPatternPool(
            name="test_pool",
            match_rules=[match_mov_reg_0_all],
            generators=[(_create_instruction, 10)],
            mutation_probability=100,
        )
        expect(pool.name == "test_pool")
        expect(len(pool.match_rules) == 1)
        expect(len(pool.generators) == 1)

    def test_pool_match_and_mutate(self):
        def mock_generator(operands, os_type):
            return [_create_instruction("xor", [operands[0], operands[0]], "xor")]

        pool = MutationPatternPool(
            name="test_pool",
            match_rules=[match_mov_reg_0_all],
            generators=[(mock_generator, 10)],
            mutation_probability=100,
        )

        ins1 = Instruction(address=0x1000, mnemonic="mov", operand_1="rax", operand_2="0", type="mov")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        block = BasicBlock(address=0x1000, instructions=[ins1, ins2])

        mutated_block = pool.match(block, "linux", verbose=False)
        expect(len(mutated_block.instructions) == _EXPECTED_LEN_MUTATED_BLOCK_INSTRUCTIONS_2)
        expect(mutated_block.instructions[0].mnemonic == "xor")

    def test_pool_verbose_logs_mutation_at_debug(self, caplog):
        """verbose=True emits the mutation detail to the module logger at DEBUG
        (no stdout printing), and the mutation itself still applies."""

        def gen(operands, os_type):
            return [_create_instruction("xor", [operands[0], operands[0]], "xor")]

        pool = MutationPatternPool(
            name="test_pool",
            match_rules=[match_mov_reg_0_all],
            generators=[(gen, 10)],
            mutation_probability=100,
        )
        ins1 = Instruction(address=0x1000, mnemonic="mov", operand_1="rax", operand_2="0", type="mov")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        block = BasicBlock(address=0x1000, instructions=[ins1, ins2])

        with caplog.at_level(logging.DEBUG, logger="r2morph.mutations.pattern_pool"):
            mutated_block = pool.match(block, "linux", verbose=True)

        expect(mutated_block.instructions[0].mnemonic == "xor")
        expect(any("mutation at 0x1000" in record.message for record in caplog.records))

    def test_pool_probability(self):
        def mock_generator(operands, os_type):
            return [_create_instruction("and", [operands[0], "0"], "and")]

        pool = MutationPatternPool(
            name="test_pool",
            match_rules=[match_mov_reg_0_all],
            generators=[(mock_generator, 10)],
            mutation_probability=0,
        )

        ins1 = Instruction(address=0x1000, mnemonic="mov", operand_1="rax", operand_2="0", type="mov")
        ins2 = Instruction(address=0x1005, mnemonic="mov", operand_1="rbx", operand_2="1", type="mov")
        block = BasicBlock(address=0x1000, instructions=[ins1, ins2])

        mutated_block = pool.match(block, "linux", verbose=False)
        expect(mutated_block.instructions[0].mnemonic == "mov")


class TestPatternPoolRegistry:
    def test_register_and_get_pools(self):
        clear_pattern_pools()

        pool = MutationPatternPool(
            name="test_registry_pool",
            match_rules=[match_mov_reg_0_all],
            generators=[(_create_instruction, 10)],
        )
        register_pattern_pool(pool)

        pools = get_pattern_pools()
        expect(len(pools) == 1)
        expect(pools[0].name == "test_registry_pool")

        clear_pattern_pools()

    def test_multiple_pools(self):
        clear_pattern_pools()

        pool1 = MutationPatternPool(name="pool1", match_rules=[], generators=[])
        pool2 = MutationPatternPool(name="pool2", match_rules=[], generators=[])

        register_pattern_pool(pool1)
        register_pattern_pool(pool2)

        pools = get_pattern_pools()
        expect(len(pools) == _EXPECTED_LEN_POOLS_2)

        clear_pattern_pools()


class TestGenerators:
    def test_generator_mov_reg_0(self):
        generator_mov_reg_0 = importlib.import_module("r2morph.mutations.pattern_generators").generator_mov_reg_0

        result = generator_mov_reg_0(["rax"], "linux")
        expect(len(result) == 1)
        expect(result[0].mnemonic == "mov")
        expect(result[0].operand_1 == "rax")
        expect(result[0].operand_2 == "0")

    def test_generator_xor_reg_reg(self):
        generator_xor_reg_reg = importlib.import_module("r2morph.mutations.pattern_generators").generator_xor_reg_reg

        result = generator_xor_reg_reg(["rbx"], "linux")
        expect(len(result) == 1)
        expect(result[0].mnemonic == "xor")
        expect(result[0].operand_1 == "rbx")
        expect(result[0].operand_2 == "rbx")

    def test_generator_and_reg_0(self):
        generator_and_reg_0 = importlib.import_module("r2morph.mutations.pattern_generators").generator_and_reg_0

        result = generator_and_reg_0(["rcx"], "linux")
        expect(len(result) == 1)
        expect(result[0].mnemonic == "and")

    def test_generator_inc_to_add(self):
        generator_inc_to_add = importlib.import_module("r2morph.mutations.pattern_generators").generator_inc_to_add

        result = generator_inc_to_add(["rax"], "linux")
        expect(len(result) == 1)
        expect(result[0].mnemonic == "add")
        expect(result[0].operand_1 == "rax")
        expect(result[0].operand_2 == "1")


class TestMatchResult:
    def test_match_result_creation(self):
        result = MatchResult(index=5, length=2, operands=["rax", "rbx"])
        expect(result.index == _EXPECTED_RESULT_INDEX_5)
        expect(result.length == _EXPECTED_RESULT_LENGTH_2)
        expect(result.operands == ["rax", "rbx"])

    def test_match_result_default_operands(self):
        result = MatchResult(index=0, length=1)
        expect(result.operands == [])
