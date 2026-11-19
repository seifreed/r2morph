"""In-memory Binary double for jump-table resolution tests.

A real (non-mock) implementation of the small Binary surface that
``SwitchTableAnalyzer.resolve_jump_table`` consumes: architecture bit width
and ``read_bytes`` over a contiguous blob anchored at the table address.
"""

from __future__ import annotations

from typing import Any


class InMemoryJumpTableBinary:
    """Serves a jump table's pointer bytes from an in-memory blob."""

    def __init__(
        self,
        *,
        bits: int,
        table_address: int,
        blob: bytes,
        instructions: list[dict[str, Any]] | None = None,
        blocks: list[dict[str, Any]] | None = None,
    ) -> None:
        self._bits = bits
        self._table_address = table_address
        self._blob = blob
        self._instructions = instructions or []
        self._blocks = blocks or []

    def get_arch_info(self) -> dict[str, Any]:
        return {"bits": self._bits}

    def read_bytes(self, address: int, size: int) -> bytes:
        start = address - self._table_address
        if start < 0:
            return b""
        chunk = self._blob[start : start + size]
        return chunk if len(chunk) == size else b""

    def get_function_disasm(self, _function_address: int) -> list[dict[str, Any]]:
        return self._instructions

    def get_basic_blocks(self, _function_address: int) -> list[dict[str, Any]]:
        return self._blocks
