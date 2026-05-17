"""A real in-memory binary double for exercising ConstantUnfoldingPass.

This is a concrete implementation (never unittest.mock): it keeps a real
mutable byte buffer and applies real write/nop_fill semantics so the pass
operates on observable state, not on a programmed mock.
"""

from __future__ import annotations


class InMemoryUnfoldBinary:
    """In-memory byte buffer with the minimal surface the pass writes through.

    ``assemble`` returns a fixed encoding for any instruction so the test
    controls the replacement size deterministically. ``nop_fill`` can be
    configured to fail, which is the condition the rollback fix guards.
    """

    NOP = 0x90

    def __init__(self, *, base_addr: int, contents: bytes, assembled: bytes, nop_fill_succeeds: bool) -> None:
        self._base = base_addr
        self._buffer = bytearray(contents)
        self._assembled = assembled
        self._nop_fill_succeeds = nop_fill_succeeds
        self.reload_called = False

    def _offset(self, addr: int) -> int:
        return addr - self._base

    def assemble(self, instruction: str, addr: int) -> bytes:
        return self._assembled

    def read_bytes(self, addr: int, size: int) -> bytes:
        start = self._offset(addr)
        return bytes(self._buffer[start : start + size])

    def write_bytes(self, addr: int, data: bytes) -> bool:
        start = self._offset(addr)
        self._buffer[start : start + len(data)] = data
        return True

    def nop_fill(self, addr: int, size: int) -> bool:
        if not self._nop_fill_succeeds:
            return False
        start = self._offset(addr)
        self._buffer[start : start + size] = bytes([self.NOP] * size)
        return True

    def reload(self) -> None:
        self.reload_called = True
