from __future__ import annotations

from r2morph.analysis.switch_table_detection import (
    detect_plt_got_thunks,
    detect_tail_calls,
    is_plt_stub_pattern,
)
from tests.utils.assertions import expect

_EXPECTED_DETECT_PLT_GOT_THUNKS_BINARY_8192 = 0x2000


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

    expect(is_plt_stub_pattern(b"\xff\x25\x00\x00\x00\x00"))
    expect(detect_tail_calls(binary, {8192: "target"}, 4096) == [(4096, 8192)])
    expect(not (_EXPECTED_DETECT_PLT_GOT_THUNKS_BINARY_8192 not in detect_plt_got_thunks(binary)))
