from __future__ import annotations

from r2morph.analysis.switch_table_detection import (
    detect_plt_got_thunks,
    detect_tail_calls,
    is_plt_stub_pattern,
)


class _Binary:
    def get_sections(self):
        return [
            {"name": ".plt", "addr": 0x2000, "size": 32},
        ]

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b"\xff\x25" + b"\x00" * 14 + b"\x90" * 16

    def get_function_disasm(self, address: int):
        return [
            {"offset": 0x1000, "type": "jmp", "opcode": "jmp 0x2000"},
            {"offset": 0x1004, "type": "mov", "opcode": "mov eax, ebx"},
        ]


def test_switch_table_detection_contract() -> None:
    binary = _Binary()

    assert is_plt_stub_pattern(b"\xff\x25\x00\x00\x00\x00")
    assert detect_tail_calls(binary, {0x2000: "target"}, 0x1000) == [(0x1000, 0x2000)]
    assert 0x2000 in detect_plt_got_thunks(binary)
