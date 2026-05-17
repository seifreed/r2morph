"""Real in-memory Binary double for exercising FunctionOutliningPass.apply.

Not unittest.mock: a concrete object over a sparse {base: bytearray}
address space serving get_functions/get_basic_blocks/get_sections,
r2.cmdj("pdj ...") (per-block instructions), r2.cmd("p8 ...") (cave
scan), read_bytes and write_bytes. The far executable section places
its cave > 2 GiB from the function so the e9 rel32 offset overflows
int32.
"""

from __future__ import annotations

import re
from typing import Any

_P8 = re.compile(r"p8\s+(\d+)\s+@\s+0x([0-9a-fA-F]+)")
_PDJ = re.compile(r"pdj\s+(\d+)\s+@\s+(\d+)")


class _OutliningR2:
    def __init__(self, owner: InMemoryOutliningBinary, pdj: dict[int, list[dict[str, Any]]]) -> None:
        self._owner = owner
        self._pdj = pdj

    def cmd(self, command: str) -> str:
        m = _P8.search(command)
        if not m:
            return ""
        return self._owner.read_bytes(int(m.group(2), 16), int(m.group(1))).hex()

    def cmdj(self, command: str) -> list[dict[str, Any]]:
        m = _PDJ.search(command)
        if not m:
            return []
        return self._pdj.get(int(m.group(2)), [])


class InMemoryOutliningBinary:
    def __init__(
        self,
        *,
        regions: dict[int, bytes],
        functions: list[dict[str, Any]],
        blocks: list[dict[str, Any]],
        pdj: dict[int, list[dict[str, Any]]],
        sections: list[dict[str, Any]],
    ) -> None:
        self._regions = {base: bytearray(data) for base, data in regions.items()}
        self._functions = functions
        self._blocks = blocks
        self._sections = sections
        self.r2 = _OutliningR2(self, pdj)

    def _region_for(self, addr: int) -> tuple[int, bytearray] | None:
        for base, buf in self._regions.items():
            if base <= addr < base + len(buf):
                return base, buf
        return None

    def get_functions(self) -> list[dict[str, Any]]:
        return self._functions

    def get_basic_blocks(self, func_addr: int) -> list[dict[str, Any]]:
        return self._blocks

    def get_sections(self) -> list[dict[str, Any]]:
        return self._sections

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
