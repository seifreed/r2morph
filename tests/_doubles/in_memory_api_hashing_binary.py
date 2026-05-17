"""Real in-memory Binary double for exercising APIHashingPass.apply.

Not unittest.mock: a concrete object over a single mutable byte buffer
serving get_sections, r2.cmd("p8 ..."), r2.cmdj("iij"/"axtj ..."),
read_bytes and write_bytes consistently, so CaveFinder + the pass
operate on real, observable state.
"""

from __future__ import annotations

import re
from typing import Any

_P8 = re.compile(r"p8\s+(\d+)\s+@\s+0x([0-9a-fA-F]+)")


class _ApiHashingR2:
    def __init__(self, owner: InMemoryAPIHashingBinary, imports: list[dict[str, Any]], xrefs: list[dict[str, Any]]):
        self._owner = owner
        self._imports = imports
        self._xrefs = xrefs

    def cmd(self, command: str) -> str:
        m = _P8.search(command)
        if not m:
            return ""
        size = int(m.group(1))
        addr = int(m.group(2), 16)
        return self._owner.read_bytes(addr, size).hex()

    def cmdj(self, command: str) -> list[dict[str, Any]]:
        if command.startswith("iij"):
            return self._imports
        if command.startswith("axtj"):
            return self._xrefs
        return []


class InMemoryAPIHashingBinary:
    def __init__(
        self,
        *,
        base_addr: int,
        contents: bytes,
        section: dict[str, Any],
        imports: list[dict[str, Any]],
        xrefs: list[dict[str, Any]],
    ) -> None:
        self._base = base_addr
        self._buf = bytearray(contents)
        self._section = section
        self.r2 = _ApiHashingR2(self, imports, xrefs)

    def get_sections(self) -> list[dict[str, Any]]:
        return [self._section]

    def read_bytes(self, addr: int, size: int) -> bytes:
        start = addr - self._base
        return bytes(self._buf[start : start + size])

    def write_bytes(self, addr: int, data: bytes) -> bool:
        start = addr - self._base
        self._buf[start : start + len(data)] = data
        return True
