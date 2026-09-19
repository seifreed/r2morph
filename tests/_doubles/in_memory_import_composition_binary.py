"""Concrete in-memory binary for import-pass composition coverage."""

from __future__ import annotations

import re
import struct
from typing import Any

_P8 = re.compile(r"p8\s+(\d+)\s+@\s+0x([0-9a-fA-F]+)")
_BASE = 0x1000
_PLT = 0x2000
_CALL_SITE = _BASE
_NOP_ANCHOR = _BASE + 0x80
_BUFFER_SIZE = 0x100


class _ImportCompositionR2:
    def __init__(self, owner: InMemoryImportCompositionBinary) -> None:
        self._owner = owner

    def cmd(self, command: str) -> str:
        match = _P8.search(command)
        if match is None:
            return ""
        return self._owner.read_bytes(int(match.group(2), 16), int(match.group(1))).hex()

    def cmdj(self, command: str) -> list[dict[str, Any]]:
        if command.startswith("iij"):
            return [{"name": "MyApi", "plt": _PLT, "type": "FUNC", "libname": "lib"}]
        if command.startswith("axtj"):
            return [{"from": _CALL_SITE, "type": "CALL"}]
        return []


class InMemoryImportCompositionBinary:
    """Mutable bytes plus the loader metadata required by both import passes."""

    def __init__(self) -> None:
        self._buffer = bytearray(b"\xcc" * _BUFFER_SIZE)
        relative_call = _PLT - (_CALL_SITE + 5)
        self._buffer[:5] = b"\xe8" + struct.pack("<i", relative_call)
        self._buffer[0x40:0x80] = b"\x90" * 0x40
        self._buffer[0x7F] = 0xCC
        self._buffer[0x80:0x83] = b"\x48\x89\xc0"
        self._buffer[0x83:0x86] = b"\x4d\x89\xd2"
        self._buffer[0x86:0x89] = b"\x48\x89\xc0"
        self._buffer[0x89:0x8C] = b"\x4d\x89\xd2"
        self._buffer[0x8C] = 0xC3
        self.r2 = _ImportCompositionR2(self)

    def analyze(self, level: str = "aa") -> None:
        del level

    def is_analyzed(self) -> bool:
        return True

    def get_arch_info(self) -> dict[str, Any]:
        return {"arch": "x86", "bits": 64, "format": "ELF"}

    def get_arch_family(self) -> tuple[str, int]:
        return "x86", 64

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "vaddr": _BASE, "vsize": _BUFFER_SIZE, "perm": "r-x"}]

    def get_functions(self) -> list[dict[str, Any]]:
        return [
            {"addr": _CALL_SITE, "size": 5, "name": "call_site"},
            {"addr": _NOP_ANCHOR, "size": 13, "name": "nop_anchor"},
        ]

    def get_function_disasm(self, address: int) -> list[dict[str, Any]]:
        if address == _CALL_SITE:
            return [{"addr": _CALL_SITE, "size": 5, "disasm": "call 0x2000", "type": "call"}]
        if address == _NOP_ANCHOR:
            return [
                {"addr": _NOP_ANCHOR, "size": 3, "disasm": "mov rax, rax", "type": "mov"},
                {"addr": _NOP_ANCHOR + 3, "size": 3, "disasm": "mov r10, r10", "type": "mov"},
                {"addr": _NOP_ANCHOR + 6, "size": 3, "disasm": "mov rax, rax", "type": "mov"},
                {"addr": _NOP_ANCHOR + 9, "size": 3, "disasm": "mov r10, r10", "type": "mov"},
                {"addr": _NOP_ANCHOR + 12, "size": 1, "disasm": "ret", "type": "ret"},
            ]
        return []

    def read_bytes(self, address: int, size: int) -> bytes:
        start = address - _BASE
        if start < 0 or start >= len(self._buffer):
            return b""
        return bytes(self._buffer[start : start + size])

    def write_bytes(self, address: int, data: bytes) -> bool:
        start = address - _BASE
        if start < 0 or start + len(data) > len(self._buffer):
            return False
        self._buffer[start : start + len(data)] = data
        return True

    def nop_fill(self, address: int, size: int) -> bool:
        return self.write_bytes(address, b"\x90" * size)
