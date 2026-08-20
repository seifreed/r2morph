"""Contracts for semantic validation helpers."""

from r2morph.mutations.semantic_validation_helpers import (
    ALL_REGISTERS_64,
    CONTROL_FLOW_OPCODES,
    POP_OPCODES,
    PRESERVED_REGISTERS_64,
    PUSH_OPCODES,
    SCRATCH_REGISTERS_64,
    UNSAFE_OPCODES,
    get_address,
    get_jump_target,
    get_mnemonic,
    get_operand,
)
from tests.utils.assertions import expect

_EXPECTED_GET_ADDRESS_ADDRESS_4096_4096 = 4096
_EXPECTED_GET_ADDRESS_ADDR_0X1000_4096 = 0x1000
_EXPECTED_GET_ADDRESS_ADDR_0X1000_4096_2 = 0x1000
_EXPECTED_GET_JUMP_TARGET_JUMP_0X2000_8192 = 0x2000
_EXPECTED_GET_JUMP_TARGET_TARGET_0X3000_12288 = 0x3000


def test_instruction_parsers_handle_common_shapes() -> None:
    expect(get_mnemonic({"mnemonic": "MOV"}) == "mov")
    expect(get_mnemonic({"type": "CALL"}) == "call")
    expect(get_address({"addr": 4096}) == _EXPECTED_GET_ADDRESS_ADDR_0X1000_4096)
    expect(get_address({"address": 4096}) == _EXPECTED_GET_ADDRESS_ADDRESS_4096_4096)
    expect(get_address({"addr": "0x1000"}) == _EXPECTED_GET_ADDRESS_ADDR_0X1000_4096_2)

    ins = {"operands": ["rax", "rbx"]}
    expect(get_operand(ins, 0) == "rax")
    expect(get_operand(ins, 1) == "rbx")

    ins2 = {"operands": {"0": "rcx", "1": "rdx"}}
    expect(get_operand(ins2, 0) == "rcx")
    expect(get_operand(ins2, 1) == "rdx")

    expect(get_jump_target({"jump": "0x2000"}) == _EXPECTED_GET_JUMP_TARGET_JUMP_0X2000_8192)
    expect(get_jump_target({"target": 12288}) == _EXPECTED_GET_JUMP_TARGET_TARGET_0X3000_12288)


def test_policy_tables_are_canonical() -> None:
    expect(PRESERVED_REGISTERS_64 == ["rbx", "rbp", "r12", "r13", "r14", "r15"])
    expect(SCRATCH_REGISTERS_64[-1] == "r11")
    expect(ALL_REGISTERS_64[:2] == ["rbx", "rbp"])
    expect(not ("push" not in PUSH_OPCODES))
    expect(not ("popq" not in POP_OPCODES))
    expect(not ("call" not in CONTROL_FLOW_OPCODES))
    expect(not ("ud2" not in UNSAFE_OPCODES))
