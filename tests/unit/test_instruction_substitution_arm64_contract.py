from __future__ import annotations

from r2morph.mutations.instruction_substitution_arm64 import apply_arm64_mov_substitution
from tests.utils.assertions import expect

_EXPECTED_ADDR_4096 = 0x1000
_EXPECTED_ADDR_8192 = 0x2000
_EXPECTED_BINARY_WRITES_0_0_4096 = 0x1000
_EXPECTED_RESULT_MUTATIONS_APPLIED_2 = 2
_EXPECTED_RESULT_TOTAL_FUNCTIONS_2 = 2


class _Binary:
    def __init__(self, instructions: list[dict[str, object]] | None = None) -> None:
        self.writes: list[tuple[int, bytes]] = []
        self.instructions = instructions

    def get_functions(self):
        return [
            {"name": "main", "offset": 0x1000, "size": 64},
            {"name": "tiny", "offset": 0x2000, "size": 8},
        ]

    def get_function_disasm(self, addr: int):
        if self.instructions is not None:
            return self.instructions
        if addr == _EXPECTED_ADDR_4096:
            return [
                {"disasm": "mov x0, 0x1", "addr": 0x1000, "size": 4},
                {"disasm": "mov x1, 0x2", "addr": 0x1004, "size": 4},
            ]
        if addr == _EXPECTED_ADDR_8192:
            return [{"disasm": "mov x0, 0x3", "addr": 0x2000, "size": 4}]
        raise ValueError(addr)

    def assemble(self, insn: str, _func_addr: int):
        table = {
            "add x0, xzr, 0x1": b"\xe0\x07\x00\x91",
            "add x1, xzr, 0x2": b"\xe1\x0b\x00\x91",
            "add x0, xzr, 0x3": b"\xe0\x0f\x00\x91",
            "add x0, xzr, 0x1, lsl 12": b"\xe0\x07\x40\x91",
        }
        return table.get(insn)

    def write_bytes(self, addr: int, data: bytes) -> bool:
        self.writes.append((addr, data))
        return True


def test_arm64_mov_substitution_helper_applies_distinct_add_writes() -> None:
    binary = _Binary()
    result = apply_arm64_mov_substitution(binary, max_substitutions=4)

    expect(result["mutations_applied"] == _EXPECTED_RESULT_MUTATIONS_APPLIED_2)
    expect(result["functions_mutated"] == 1)
    expect(result["total_functions"] == _EXPECTED_RESULT_TOTAL_FUNCTIONS_2)
    expect(binary.writes[0][0] == _EXPECTED_BINARY_WRITES_0_0_4096)


def test_arm64_mov_substitution_helper_accepts_shifted_immediate_encoding() -> None:
    binary = _Binary([{"disasm": "mov x0, 0x1000", "addr": 0x1000, "size": 4}])

    result = apply_arm64_mov_substitution(binary, max_substitutions=4)

    expect(result["mutations_applied"] == 1)


def test_arm64_mov_substitution_helper_rejects_unrepresentable_immediate() -> None:
    binary = _Binary([{"disasm": "mov x0, 0x1001", "addr": 0x1000, "size": 4}])

    result = apply_arm64_mov_substitution(binary, max_substitutions=4)

    expect(result["mutations_applied"] == 0)
