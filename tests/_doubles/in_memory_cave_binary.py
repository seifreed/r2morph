"""Real in-memory Binary double exposing one large executable cave.

Not unittest.mock: a concrete object serving the methods the cave
injector chain needs -- ``get_arch_info``, ``get_sections``, an ``r2``
with ``cmd("p8 <n> @ 0x<addr>")`` returning a zero-filled (cave) hex
dump, and ``write_bytes`` that records every write. It lets
``CodeCaveInjector.inject_with_trampolines`` run end-to-end without
radare2, LIEF or touching disk.
"""

from __future__ import annotations

import re
from typing import Any

_P8 = re.compile(r"p8\s+(\d+)\s+@\s+0x([0-9a-fA-F]+)")


class _CaveR2:
    def __init__(self, fill_byte: int) -> None:
        self._fill_byte = fill_byte

    def cmd(self, command: str) -> str:
        match = _P8.search(command)
        if not match:
            return ""
        return (bytes([self._fill_byte]) * int(match.group(1))).hex()


class InMemoryCaveBinary:
    def __init__(self, cave_byte: int = 0, functions: list[dict[str, int]] | None = None) -> None:
        self._cave_byte = cave_byte
        self._functions = functions or []
        self.r2 = _CaveR2(cave_byte)
        self.writes: list[tuple[int, bytes]] = []

    def get_arch_info(self) -> dict[str, Any]:
        return {"format": "ELF64", "arch": "x86_64", "bits": 64}

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "perm": "rx"}]

    def write_bytes(self, addr: int, data: bytes) -> bool:
        self.writes.append((addr, bytes(data)))
        return True

    def read_bytes(self, addr: int, size: int) -> bytes:
        return bytes([self._cave_byte]) * size

    def get_functions(self) -> list[dict[str, int]]:
        return list(self._functions)
