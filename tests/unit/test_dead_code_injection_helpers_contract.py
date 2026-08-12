from r2morph.mutations.dead_code_injection_helpers import (
    find_injection_points,
    generate_dead_code,
    generate_dead_code_for_size,
    is_safe_injection_point,
)


class _Binary:
    def get_arch_family(self):
        return "x86", 32

    def assemble(self, insn: str, function_addr: int | None = None):
        table = {
            "mov eax, eax": b"\x89\xc0",
            "nop": b"\x90",
        }
        return table.get(insn)


def test_dead_code_injection_helpers_cover_the_core_paths() -> None:
    instructions = [
        {"offset": 0x1000, "size": 1, "opcode": "nop"},
        {"offset": 0x1001, "size": 1, "opcode": "nop"},
        {"offset": 0x1002, "size": 1, "opcode": "mov"},
        {"offset": 0x1003, "size": 1, "opcode": "ret"},
        {"offset": 0x1004, "size": 1, "opcode": "nop"},
    ]
    binary = _Binary()

    points = find_injection_points(instructions, 2)
    assert points and points[0]["type"] == "padding"
    assert is_safe_injection_point(instructions[0], instructions, 0) is True
    assert is_safe_injection_point(instructions[2], instructions, 2) is False
    assert generate_dead_code(binary, "simple")
    generated = generate_dead_code_for_size(binary, 4, 0x1000, "simple")
    assert generated is not None and len(generated) == 4
