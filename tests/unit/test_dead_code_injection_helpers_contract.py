import r2morph.mutations.dead_code_injection_helpers as dead_code_helpers
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


def test_dead_code_injection_helpers_cover_the_core_paths(monkeypatch) -> None:
    monkeypatch.setattr(dead_code_helpers, "generate_dead_code_for_arch", lambda arch, bits, complexity: ["mov eax, eax"])
    monkeypatch.setattr(dead_code_helpers, "generate_nop_sequence", lambda arch, bits, size: b"N" * size)

    instructions = [
        {"offset": 0x1000, "size": 1, "mnemonic": "nop"},
        {"offset": 0x1001, "size": 1, "mnemonic": "nop"},
        {"offset": 0x1002, "size": 1, "mnemonic": "mov"},
        {"offset": 0x1003, "size": 1, "mnemonic": "ret"},
        {"offset": 0x1004, "size": 1, "mnemonic": "nop"},
    ]
    binary = _Binary()

    points = find_injection_points(instructions, 2)
    assert points and points[0]["type"] == "padding"
    assert is_safe_injection_point(instructions[0], instructions, 0) is True
    assert is_safe_injection_point(instructions[2], instructions, 2) is False
    assert generate_dead_code(binary, "simple") == ["mov eax, eax"]
    assert generate_dead_code_for_size(binary, 4, 0x1000, "simple") == b"\x89\xc0NN"
