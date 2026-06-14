"""
Pattern-matching rules for instruction mutation.

Each ``match_*`` scans a list of instructions and returns the
:class:`~r2morph.mutations.pattern_types.MatchResult` positions a generator can
rewrite. Rules are pure leaf functions depending only on
:mod:`r2morph.mutations.pattern_types`; register-size metadata is pulled lazily
from the register tracker to keep the import graph acyclic.
"""

from r2morph.mutations.pattern_types import Instruction, MatchResult


def match_mov_reg_reg_reg64_reg16(instructions: list[Instruction]) -> list[MatchResult]:
    from r2morph.analysis.register_tracker import REG_16, REG_64, REG_SIZES_MAP

    matches = []

    for idx, ins in enumerate(instructions):
        if not hasattr(ins, "mnemonic") or ins.mnemonic != "mov":
            continue

        if not hasattr(ins, "operand_1") or not hasattr(ins, "operand_2"):
            continue

        op1 = ins.operand_1 if hasattr(ins, "operand_1") else ""
        op2 = ins.operand_2 if hasattr(ins, "operand_2") else ""

        if not isinstance(op1, str) or not isinstance(op2, str):
            continue

        op1_size = REG_SIZES_MAP.get(op1.lower() if op1 else "", 0)
        op2_size = REG_SIZES_MAP.get(op2.lower() if op2 else "", 0)

        if (op1_size & (REG_64 | REG_16)) and (op2_size & (REG_64 | REG_16)):
            matches.append(MatchResult(index=idx, length=1, operands=[op1, op2]))

    return matches


def match_push_pop_reg64_reg16(instructions: list[Instruction]) -> list[MatchResult]:
    from r2morph.analysis.register_tracker import REG_SIZES_MAP

    matches = []

    for idx in range(len(instructions) - 1):
        ins1 = instructions[idx]
        ins2 = instructions[idx + 1]

        if not hasattr(ins1, "mnemonic") or ins1.mnemonic != "push":
            continue
        if not hasattr(ins2, "mnemonic") or ins2.mnemonic != "pop":
            continue

        op1 = getattr(ins1, "operand_1", "")
        op2 = getattr(ins2, "operand_1", "")

        if not isinstance(op1, str) or not isinstance(op2, str):
            continue

        if REG_SIZES_MAP.get(op1.lower() if op1 else "", 0) and REG_SIZES_MAP.get(op2.lower() if op2 else "", 0):
            matches.append(MatchResult(index=idx, length=2, operands=[op2, op1]))

    return matches


def _match_reg_zero_imm(instructions: list[Instruction], mnemonic: str) -> list[MatchResult]:
    from r2morph.analysis.register_tracker import REG_SIZES_MAP

    matches = []

    for idx in range(len(instructions) - 1):
        ins = instructions[idx]
        next_ins = instructions[idx + 1]

        if not hasattr(ins, "mnemonic") or ins.mnemonic != mnemonic:
            continue

        op1 = getattr(ins, "operand_1", "")
        op2 = getattr(ins, "operand_2", "")

        if not isinstance(op1, str) or not isinstance(op2, str):
            continue

        if not REG_SIZES_MAP.get(op1.lower() if op1 else "", 0):
            continue

        if op2 != "0":
            continue

        if hasattr(next_ins, "type") and next_ins.type == "cjmp":
            continue

        matches.append(MatchResult(index=idx, length=1, operands=[op1]))

    return matches


def _match_reg_self_op(instructions: list[Instruction], mnemonic: str) -> list[MatchResult]:
    from r2morph.analysis.register_tracker import REG_SIZES_MAP

    matches = []

    for idx in range(len(instructions) - 1):
        ins = instructions[idx]
        next_ins = instructions[idx + 1]

        if not hasattr(ins, "mnemonic") or ins.mnemonic != mnemonic:
            continue

        op1 = getattr(ins, "operand_1", "")
        op2 = getattr(ins, "operand_2", "")

        if not isinstance(op1, str) or not isinstance(op2, str):
            continue

        if not REG_SIZES_MAP.get(op1.lower() if op1 else "", 0):
            continue

        if op1.lower() != op2.lower():
            continue

        if hasattr(next_ins, "type") and next_ins.type == "cjmp":
            continue

        matches.append(MatchResult(index=idx, length=1, operands=[op1]))

    return matches


def match_mov_reg_0_all(instructions: list[Instruction]) -> list[MatchResult]:
    return _match_reg_zero_imm(instructions, "mov")


def match_xor_reg_reg_all(instructions: list[Instruction]) -> list[MatchResult]:
    return _match_reg_self_op(instructions, "xor")


def match_and_reg_0_all(instructions: list[Instruction]) -> list[MatchResult]:
    return _match_reg_zero_imm(instructions, "and")


def match_sub_reg_same(instructions: list[Instruction]) -> list[MatchResult]:
    return _match_reg_self_op(instructions, "sub")


def _match_unary_reg(instructions: list[Instruction], mnemonic: str) -> list[MatchResult]:
    from r2morph.analysis.register_tracker import REG_32, REG_64, REG_SIZES_MAP

    matches = []

    for idx in range(len(instructions) - 1):
        ins = instructions[idx]
        next_ins = instructions[idx + 1]

        if not hasattr(ins, "mnemonic") or ins.mnemonic != mnemonic:
            continue

        op1 = getattr(ins, "operand_1", "")

        if not isinstance(op1, str):
            continue

        reg_size = REG_SIZES_MAP.get(op1.lower() if op1 else "", 0)
        if not (reg_size & (REG_64 | REG_32)):
            continue

        if hasattr(next_ins, "type") and next_ins.type == "cjmp":
            continue

        matches.append(MatchResult(index=idx, length=1, operands=[op1]))

    return matches


def match_inc_reg(instructions: list[Instruction]) -> list[MatchResult]:
    return _match_unary_reg(instructions, "inc")


def match_dec_reg(instructions: list[Instruction]) -> list[MatchResult]:
    return _match_unary_reg(instructions, "dec")


def _match_shift_reg_imm(instructions: list[Instruction], mnemonics: tuple[str, ...]) -> list[MatchResult]:
    from r2morph.analysis.register_tracker import REG_32, REG_64, REG_SIZES_MAP

    matches = []
    shift_values = {"1", "2", "4", "8"}

    for idx in range(len(instructions) - 1):
        ins = instructions[idx]
        next_ins = instructions[idx + 1]

        if not hasattr(ins, "mnemonic") or ins.mnemonic not in mnemonics:
            continue

        op1 = getattr(ins, "operand_1", "")
        op2 = getattr(ins, "operand_2", "")

        if not isinstance(op1, str) or not isinstance(op2, str):
            continue

        reg_size = REG_SIZES_MAP.get(op1.lower() if op1 else "", 0)
        if not (reg_size & (REG_64 | REG_32)):
            continue

        op2_clean = op2.strip().lower().lstrip("0x")
        if op2_clean not in shift_values and op2 not in shift_values:
            continue

        if hasattr(next_ins, "type") and next_ins.type == "cjmp":
            continue

        matches.append(MatchResult(index=idx, length=1, operands=[op1, op2]))

    return matches


def match_shl_reg_imm(instructions: list[Instruction]) -> list[MatchResult]:
    return _match_shift_reg_imm(instructions, ("shl", "sal"))


def match_shr_reg_imm(instructions: list[Instruction]) -> list[MatchResult]:
    return _match_shift_reg_imm(instructions, ("shr",))


def _match_binary_reg_imm_small(instructions: list[Instruction], mnemonic: str) -> list[MatchResult]:
    from r2morph.analysis.register_tracker import REG_SIZES_MAP

    matches = []

    for idx in range(len(instructions) - 1):
        ins = instructions[idx]
        next_ins = instructions[idx + 1]

        if not hasattr(ins, "mnemonic") or ins.mnemonic != mnemonic:
            continue

        op1 = getattr(ins, "operand_1", "")
        op2 = getattr(ins, "operand_2", "")

        if not isinstance(op1, str) or not isinstance(op2, str):
            continue

        if not REG_SIZES_MAP.get(op1.lower() if op1 else "", 0):
            continue

        try:
            imm_val = int(op2, 0) if op2.startswith("0x") else int(op2)
            if not (1 <= imm_val <= 8):
                continue
        except ValueError:
            continue

        if hasattr(next_ins, "type") and next_ins.type == "cjmp":
            continue

        matches.append(MatchResult(index=idx, length=1, operands=[op1, op2]))

    return matches


def match_add_reg_imm_small(instructions: list[Instruction]) -> list[MatchResult]:
    return _match_binary_reg_imm_small(instructions, "add")


def match_sub_reg_imm_small(instructions: list[Instruction]) -> list[MatchResult]:
    return _match_binary_reg_imm_small(instructions, "sub")


def match_lea_reg_off(instructions: list[Instruction]) -> list[MatchResult]:
    from r2morph.analysis.register_tracker import REG_64, REG_SIZES_MAP

    matches = []

    for idx in range(len(instructions) - 1):
        ins = instructions[idx]
        next_ins = instructions[idx + 1]

        if not hasattr(ins, "mnemonic") or ins.mnemonic != "lea":
            continue

        op1 = getattr(ins, "operand_1", "")
        op2 = getattr(ins, "operand_2", "")

        if not isinstance(op1, str) or not isinstance(op2, str):
            continue

        reg_size = REG_SIZES_MAP.get(op1.lower() if op1 else "", 0)
        if not (reg_size & REG_64):
            continue

        if not op2.startswith("[") or not op2.endswith("]"):
            continue

        if hasattr(next_ins, "type") and next_ins.type == "cjmp":
            continue

        matches.append(MatchResult(index=idx, length=1, operands=[op1, op2]))

    return matches
