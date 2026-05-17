"""Real sparse-address-space Binary double for APIHashingPass.apply.

Not unittest.mock: a concrete object over a {base: bytearray} region
map (so a cave can sit > 2 GiB from a call site / PLT without a
multi-GiB buffer) serving get_sections, r2.cmd("p8 ..."),
r2.cmdj("iij"/"axtj ..."), read_bytes and write_bytes.
"""

from __future__ import annotations

import re
from typing import Any

_P8 = re.compile(r"p8\s+(\d+)\s+@\s+0x([0-9a-fA-F]+)")


class _SparseApiR2:
    def __init__(
        self, owner: InMemoryAPIHashingSparseBinary, imports: list[dict[str, Any]], xrefs: list[dict[str, Any]]
    ) -> None:
        self._owner = owner
        self._imports = imports
        self._xrefs = xrefs

    def cmd(self, command: str) -> str:
        m = _P8.search(command)
        if not m:
            return ""
        return self._owner.read_bytes(int(m.group(2), 16), int(m.group(1))).hex()

    def cmdj(self, command: str) -> list[dict[str, Any]]:
        if command.startswith("iij"):
            return self._imports
        if command.startswith("axtj"):
            return self._xrefs
        return []


class InMemoryAPIHashingSparseBinary:
    def __init__(
        self,
        *,
        regions: dict[int, bytes],
        section: dict[str, Any],
        imports: list[dict[str, Any]],
        xrefs: list[dict[str, Any]],
    ) -> None:
        self._regions = {base: bytearray(data) for base, data in regions.items()}
        self._section = section
        self.r2 = _SparseApiR2(self, imports, xrefs)

    def _region_for(self, addr: int) -> tuple[int, bytearray] | None:
        for base, buf in self._regions.items():
            if base <= addr < base + len(buf):
                return base, buf
        return None

    def get_sections(self) -> list[dict[str, Any]]:
        return [self._section]

    def read_bytes(self, addr: int, size: int) -> bytes:
        found = self._region_for(addr)
        if found is None:
            return b""
        base, buf = found
        start = addr - base
        return bytes(buf[start : start + size])

    def write_bytes(self, addr: int, data: bytes) -> bool:
        found = self._region_for(addr)
        if found is None:
            return False
        base, buf = found
        start = addr - base
        buf[start : start + len(data)] = data
        return True
