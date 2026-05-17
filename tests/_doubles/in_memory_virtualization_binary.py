"""Real in-memory Binary double for exercising CodeVirtualizationPass.apply.

Not unittest.mock: a concrete object backed by a real mutable byte
buffer. ``read_bytes`` can be configured to fail (return ``b""``) to
exercise the read-failure path without monkeypatching.
"""

from __future__ import annotations

from typing import Any


class _ProbeR2:
    def __init__(self, insns: list[dict[str, Any]]) -> None:
        self._insns = insns

    def cmdj(self, cmd: str) -> list[dict[str, Any]]:
        return self._insns


class InMemoryVirtualizationBinary:
    """Minimal Binary surface CodeVirtualizationPass.apply drives."""

    def __init__(
        self,
        *,
        base_addr: int,
        contents: bytes,
        insns: list[dict[str, Any]],
        reads_fail: bool,
    ) -> None:
        self._base = base_addr
        self._buf = bytearray(contents)
        self._reads_fail = reads_fail
        self.r2 = _ProbeR2(insns)
        self.reload_called = 0

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"addr": self._base, "size": len(self._buf)}]

    def get_arch_info(self) -> dict[str, Any]:
        return {"arch": "x86_64", "bits": 64}

    def get_basic_blocks(self, func_addr: int) -> list[dict[str, Any]]:
        return [{"addr": self._base, "size": len(self._buf)}]

    def read_bytes(self, addr: int, size: int) -> bytes:
        if self._reads_fail:
            return b""
        start = addr - self._base
        return bytes(self._buf[start : start + size])

    def write_bytes(self, addr: int, data: bytes) -> bool:
        start = addr - self._base
        self._buf[start : start + len(data)] = data
        return True

    def reload(self) -> None:
        self.reload_called += 1
