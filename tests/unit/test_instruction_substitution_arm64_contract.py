from __future__ import annotations

from r2morph.mutations.instruction_substitution_arm64 import apply_arm64_mov_substitution


class _Binary:
    def __init__(self) -> None:
        self.writes: list[tuple[int, bytes]] = []

    def get_functions(self):
        return [
            {"name": "main", "offset": 0x1000, "size": 64},
            {"name": "tiny", "offset": 0x2000, "size": 8},
        ]

    def get_function_disasm(self, addr: int):
        if addr == 0x1000:
            return [
                {"disasm": "mov x0, 0x1", "addr": 0x1000, "size": 4},
                {"disasm": "mov x1, 0x2", "addr": 0x1004, "size": 4},
            ]
        if addr == 0x2000:
            return [{"disasm": "mov x0, 0x3", "addr": 0x2000, "size": 4}]
        raise ValueError(addr)

    def assemble(self, insn: str, _func_addr: int):
        table = {
            "movz x0, 0x1": b"\x01\x00\x80\xd2",
            "movz x1, 0x2": b"\x41\x00\x80\xd2",
            "movz x0, 0x3": b"\x61\x00\x80\xd2",
        }
        return table.get(insn)

    def write_bytes(self, addr: int, data: bytes) -> bool:
        self.writes.append((addr, data))
        return True


def test_arm64_mov_substitution_helper_applies_matching_movz_writes() -> None:
    binary = _Binary()
    result = apply_arm64_mov_substitution(binary, max_substitutions=4)

    assert result["mutations_applied"] == 2
    assert result["functions_mutated"] == 1
    assert result["total_functions"] == 2
    assert binary.writes[0][0] == 0x1000
