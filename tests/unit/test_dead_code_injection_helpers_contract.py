from r2morph.mutations.dead_code_injection_helpers import (
    find_injection_points,
    generate_dead_code,
    generate_dead_code_for_size,
    is_safe_injection_point,
)
from tests.utils.assertions import expect

_EXPECTED_LEN_GENERATED_4 = 4
_EXPECTED_OPERAND_COUNT = 2
_EXPECTED_PADDING_SIZE = 16


class _Binary:
    def get_arch_family(self):
        return "x86", 32

    def assemble(self, insn: str, function_addr: int | None = None):
        table = {
            "mov eax, eax": b"\x89\xc0",
            "nop": b"\x90",
        }
        return table.get(insn)


class _RecordingBinary:
    def __init__(self) -> None:
        self.instructions: list[str] = []
        self.encodings: list[bytes] = []

    def get_arch_family(self):
        return "x86", 64

    def assemble(self, insn: str, function_addr: int | None = None):
        self.instructions.append(insn)
        operands = insn.removeprefix("mov ").split(", ")
        registers = {"rbx": 3, "rcx": 1, "rdx": 2, "rsi": 6, "rdi": 7}
        if len(operands) != _EXPECTED_OPERAND_COUNT or operands[0] != operands[1]:
            return None
        register = registers[operands[0]]
        modrm = 0xC0 | (register << 3) | register
        encoded = b"\x48\x89" + bytes([modrm])
        self.encodings.append(encoded)
        return encoded


def test_dead_code_injection_helpers_cover_the_core_paths() -> None:
    instructions = [
        {"offset": 0x1000, "size": 1, "opcode": "nop"},
        {"offset": 0x1001, "size": 1, "opcode": "nop"},
        {"offset": 0x1002, "size": 1, "opcode": "mov"},
        {"offset": 0x1003, "size": 1, "opcode": "ret"},
        {"offset": 0x1004, "size": 1, "opcode": "nop"},
        {"offset": 0x1005, "size": 1, "opcode": "int3"},
        {"offset": 0x1006, "size": 1, "opcode": "int3"},
        {"offset": 0x1007, "size": 2, "opcode": "ud2"},
    ]
    binary = _Binary()

    points = find_injection_points(instructions, 2)
    expect(points == [{"addr": 0x1000, "size": 2, "type": "padding"}])
    expect(not (is_safe_injection_point(instructions[0], instructions, 0) is not True))
    expect(not (is_safe_injection_point(instructions[2], instructions, 2) is not False))
    expect(generate_dead_code(binary, "simple"))
    generated = generate_dead_code_for_size(binary, 4, 0x1000, "simple")
    expect(generated is not None and len(generated) == _EXPECTED_LEN_GENERATED_4)


def test_padding_replacement_uses_a_register_identity_instruction() -> None:
    binary = _RecordingBinary()
    generated = generate_dead_code_for_size(binary, _EXPECTED_PADDING_SIZE, 0x1000, "medium")

    expect(len(binary.instructions) == 1)
    expect(binary.instructions[0].startswith("mov "))
    operands = binary.instructions[0].removeprefix("mov ").split(", ")
    expect(len(operands) == _EXPECTED_OPERAND_COUNT and operands[0] == operands[1])
    expect(
        generated is not None and len(generated) == _EXPECTED_PADDING_SIZE and generated.startswith(binary.encodings[0])
    )
