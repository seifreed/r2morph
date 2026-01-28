from r2morph.core.instruction import Instruction
from r2morph.core.function import Function


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

    assert insn.is_jump() is True
    assert insn.is_call() is False
    assert insn.get_jump_target() == 0x401050
    assert "jmp" in str(insn)
    assert "0x401000" in repr(insn)


def test_function_helpers_and_repr():
    func = Function.from_r2_dict(
        {"offset": 0x402000, "name": "sym.test", "size": 64, "callrefs": [0x401000]}
    )
    func.instructions = [{"offset": 0x402000}, {"offset": 0x402002}]
    func.basic_blocks = [{"addr": 0x402000}, {"addr": 0x402010}]

    assert func.get_instructions_count() == 2
    assert func.get_complexity() == 2
    assert func.is_leaf() is False
    assert "sym.test" in repr(func)
