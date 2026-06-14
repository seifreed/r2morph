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


def test_instruction_parsers_handle_common_shapes() -> None:
    assert get_mnemonic({"mnemonic": "MOV"}) == "mov"
    assert get_mnemonic({"type": "CALL"}) == "call"
    assert get_address({"addr": 0x1000}) == 0x1000
    assert get_address({"address": 4096}) == 4096
    assert get_address({"addr": "0x1000"}) == 0x1000

    ins = {"operands": ["rax", "rbx"]}
    assert get_operand(ins, 0) == "rax"
    assert get_operand(ins, 1) == "rbx"

    ins2 = {"operands": {"0": "rcx", "1": "rdx"}}
    assert get_operand(ins2, 0) == "rcx"
    assert get_operand(ins2, 1) == "rdx"

    assert get_jump_target({"jump": "0x2000"}) == 0x2000
    assert get_jump_target({"target": 0x3000}) == 0x3000


def test_policy_tables_are_canonical() -> None:
    assert PRESERVED_REGISTERS_64 == ["rbx", "rbp", "r12", "r13", "r14", "r15"]
    assert SCRATCH_REGISTERS_64[-1] == "r11"
    assert ALL_REGISTERS_64[:2] == ["rbx", "rbp"]
    assert "push" in PUSH_OPCODES
    assert "popq" in POP_OPCODES
    assert "call" in CONTROL_FLOW_OPCODES
    assert "ud2" in UNSAFE_OPCODES
