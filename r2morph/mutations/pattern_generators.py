"""
Replacement-code generators for instruction pattern mutation.

Each ``generator_*`` produces a semantically equivalent instruction sequence
for a matched pattern. Generators are pure leaf functions depending only on
:mod:`r2morph.mutations.pattern_types`; the junk-enhanced variants lazily pull
in the junk generator to keep the import graph acyclic.
"""

from typing import Any

from r2morph.mutations.pattern_types import Instruction


def _create_instruction(mnemonic: str, operands: list[str], ins_type: str = "") -> Instruction:
    ins = Instruction(
        address=0,
        mnemonic=mnemonic,
        operand_1=operands[0] if len(operands) > 0 else "",
        operand_2=operands[1] if len(operands) > 1 else "",
        operand_3=operands[2] if len(operands) > 2 else "",
        operand_str=", ".join(operands),
        bytes="",
        type=ins_type if ins_type else mnemonic,
        opcode=f"{mnemonic} {', '.join(operands)}".rstrip(),
        mutated=True,
    )
    return ins


def generator_mov_reg_reg(operands: list[Any], os_type: str) -> list[Instruction]:
    dst, src = operands[0], operands[1]
    return [_create_instruction("mov", [dst, src], "mov")]


def generator_push_pop_reg(operands: list[Any], os_type: str) -> list[Instruction]:
    dst, src = operands[0], operands[1]
    push = _create_instruction("push", [src], "push")
    pop = _create_instruction("pop", [dst], "pop")
    return [push, pop]


def generator_xor_reg_reg(operands: list[Any], os_type: str) -> list[Instruction]:
    reg = operands[0]
    return [_create_instruction("xor", [reg, reg], "xor")]


def generator_mov_reg_0(operands: list[Any], os_type: str) -> list[Instruction]:
    reg = operands[0]
    return [_create_instruction("mov", [reg, "0"], "mov")]


def generator_and_reg_0(operands: list[Any], os_type: str) -> list[Instruction]:
    reg = operands[0]
    return [_create_instruction("and", [reg, "0"], "and")]


def generator_sub_reg_same(operands: list[Any], os_type: str) -> list[Instruction]:
    reg = operands[0]
    return [_create_instruction("sub", [reg, reg], "sub")]


def generator_inc_to_add(operands: list[Any], os_type: str) -> list[Instruction]:
    reg = operands[0]
    return [_create_instruction("add", [reg, "1"], "add")]


def generator_dec_to_sub(operands: list[Any], os_type: str) -> list[Instruction]:
    reg = operands[0]
    return [_create_instruction("sub", [reg, "1"], "sub")]


def generator_add_to_lea(operands: list[Any], os_type: str) -> list[Instruction]:
    reg = operands[0]
    return [_create_instruction("lea", [reg, f"[{reg} + 1]"], "lea")]


def generator_shl_to_lea(operands: list[Any], os_type: str) -> list[Instruction]:
    reg = operands[0]
    shift = operands[1] if len(operands) > 1 else "1"
    try:
        shift_val = int(shift, 0) if shift.startswith("0x") else int(shift)
        multiplier = 1 << shift_val
    except ValueError:
        multiplier = 2
    return [_create_instruction("lea", [reg, f"[{reg} * {multiplier}]"], "lea")]


def generator_push_pop_with_junk(operands: list[Any], os_type: str) -> list[Instruction]:
    from r2morph.mutations.junk_generator import create_junk_generator

    dst, src = operands[0], operands[1]

    push = _create_instruction("push", [src], "push")

    junk_gen = create_junk_generator(os_type)
    junk_size = 32
    junk = junk_gen.generate_junk_code(junk_size)

    pop = _create_instruction("pop", [dst], "pop")

    junk_ins = _create_instruction("db", [junk.hex()], "db")
    junk_ins.bytes = junk.hex()
    junk_ins.opcode = f"; junk code ({len(junk)} bytes)"

    return [push, junk_ins, pop]


def generator_xor_with_junk(operands: list[Any], os_type: str) -> list[Instruction]:
    from r2morph.mutations.junk_generator import create_junk_generator

    reg = operands[0]

    junk_gen = create_junk_generator(os_type)
    junk_size = 24
    junk = junk_gen.generate_junk_code(junk_size)

    xor_ins = _create_instruction("xor", [reg, reg], "xor")

    junk_ins = _create_instruction("db", [junk.hex()], "db")
    junk_ins.bytes = junk.hex()
    junk_ins.opcode = f"; junk code ({len(junk)} bytes)"

    return [xor_ins, junk_ins]


def generator_mov_with_junk_before(operands: list[Any], os_type: str) -> list[Instruction]:
    from r2morph.mutations.junk_generator import create_junk_generator

    if len(operands) == 1:
        reg, src = operands[0], "0"
    else:
        reg, src = operands[0], operands[1]

    junk_gen = create_junk_generator(os_type)
    junk_size = 28
    junk = junk_gen.generate_junk_code(junk_size)

    junk_ins = _create_instruction("db", [junk.hex()], "db")
    junk_ins.bytes = junk.hex()
    junk_ins.opcode = f"; junk code ({len(junk)} bytes)"

    mov_ins = _create_instruction("mov", [reg, src], "mov")

    return [junk_ins, mov_ins]


def generator_add_inc_chain(operands: list[Any], os_type: str) -> list[Instruction]:
    reg = operands[0]
    inc_ins = _create_instruction("inc", [reg], "inc")
    return [inc_ins]


def generator_dec_chain(operands: list[Any], os_type: str) -> list[Instruction]:
    reg = operands[0]
    dec_ins = _create_instruction("dec", [reg], "dec")
    return [dec_ins]
