from __future__ import annotations

from r2morph.mutations.instruction_substitution_arm64 import apply_arm64_mov_substitution
from tests.utils.assertions import expect

_EXPECTED_ADDR_4096 = 0x1000
_EXPECTED_ADDR_8192 = 0x2000
_EXPECTED_BINARY_WRITES_0_0_4096 = 0x1000
_EXPECTED_RESULT_MUTATIONS_APPLIED_2 = 2
_EXPECTED_RESULT_TOTAL_FUNCTIONS_2 = 2


class _Binary:
    def __init__(
        self,
        instructions: list[dict[str, object]] | None = None,
        assembly: dict[str, bytes] | None = None,
    ) -> None:
        self.writes: list[tuple[int, bytes]] = []
        self.instructions = instructions
        self.assembly = assembly

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
            "orr x0, xzr, 0x1": b"\xe0\x03\x40\xb2",
            "orr x1, xzr, 0x2": b"\xe1\x03\x7f\xb2",
            "orr x0, xzr, 0x3": b"\xe0\x07\x40\xb2",
            "orr x0, xzr, 0x1000": b"\xe0\x03\x74\xb2",
        }
        if self.assembly is not None:
            table.update(self.assembly)
        return table.get(insn)

    def write_bytes(self, addr: int, data: bytes) -> bool:
        self.writes.append((addr, data))
        return True


def test_arm64_mov_substitution_helper_applies_distinct_orr_writes() -> None:
    binary = _Binary()
    result = apply_arm64_mov_substitution(binary, max_substitutions=4)

    expect(result["mutations_applied"] == _EXPECTED_RESULT_MUTATIONS_APPLIED_2)
    expect(result["functions_mutated"] == 1)
    expect(result["total_functions"] == _EXPECTED_RESULT_TOTAL_FUNCTIONS_2)
    expect(binary.writes[0][0] == _EXPECTED_BINARY_WRITES_0_0_4096)


def test_arm64_mov_substitution_helper_accepts_logical_immediate_encoding() -> None:
    binary = _Binary([{"disasm": "mov x0, 0x1000", "addr": 0x1000, "size": 4}])

    result = apply_arm64_mov_substitution(binary, max_substitutions=4)

    expect(result["mutations_applied"] == 1)


def test_arm64_mov_substitution_helper_uses_zero_register_for_zero_immediate() -> None:
    binary = _Binary(
        [{"disasm": "mov w0, 0", "addr": 0x1000, "size": 4}],
        {"orr w0, wzr, wzr": b"\xe0\x03\x1f\x2a"},
    )

    result = apply_arm64_mov_substitution(binary, max_substitutions=4)

    expect(result["mutations_applied"] == 1)


def test_arm64_mov_substitution_helper_rejects_unrepresentable_immediate() -> None:
    binary = _Binary([{"disasm": "mov x0, 0x1001", "addr": 0x1000, "size": 4}])

    result = apply_arm64_mov_substitution(binary, max_substitutions=4)

    expect(result["mutations_applied"] == 0)
