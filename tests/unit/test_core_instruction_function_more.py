from r2morph.core.function import Function
from r2morph.core.instruction import Instruction
from tests.utils.assertions import expect

_EXPECTED_FUNC_GET_COMPLEXITY_2 = 2
_EXPECTED_FUNC_GET_INSTRUCTIONS_COUNT_2 = 2
_EXPECTED_INSN_GET_JUMP_TARGET_4198480 = 0x401050


def test_instruction_helpers_and_repr():
    insn = Instruction.from_r2_dict(
        {
            "offset": 0x401000,
            "disasm": "jmp 0x401050",
            "bytes": "e9 4b 00 00 00",
            "size": 5,
            "type": "jmp",
            "jump": 0x401050,
        }
    )

    expect(not (insn.is_jump() is not True))
    expect(not (insn.is_call() is not False))
    expect(insn.get_jump_target() == _EXPECTED_INSN_GET_JUMP_TARGET_4198480)
    expect(not ("jmp" not in str(insn)))
    expect(not ("0x401000" not in repr(insn)))


def test_function_helpers_and_repr():
    func = Function.from_r2_dict({"offset": 0x402000, "name": "sym.test", "size": 64, "callrefs": [0x401000]})
    func.instructions = [{"offset": 0x402000}, {"offset": 0x402002}]
    func.basic_blocks = [{"addr": 0x402000}, {"addr": 0x402010}]

    expect(func.get_instructions_count() == _EXPECTED_FUNC_GET_INSTRUCTIONS_COUNT_2)
    expect(func.get_complexity() == _EXPECTED_FUNC_GET_COMPLEXITY_2)
    expect(not (func.is_leaf() is not False))
    expect(not ("sym.test" not in repr(func)))
