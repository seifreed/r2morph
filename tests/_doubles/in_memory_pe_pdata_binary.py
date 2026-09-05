"""Real in-memory PE Binary double exposing a synthetic ``.pdata`` section.

Not unittest.mock: a concrete object serving the three methods
``ExceptionInfoReader`` needs for the PE path -- ``get_arch_info``,
``get_sections`` and ``read_bytes`` -- over a single in-memory byte
buffer at a fixed RVA. ``read_bytes`` honours the requested size but
never returns more than the buffer holds, so a declared section size
larger than the buffer models a truncated/crafted binary.
"""

from __future__ import annotations

from typing import Any


class InMemoryPEPdataBinary:
    def __init__(
        self,
        *,
        bits: int,
        pdata_addr: int,
        pdata_declared_size: int,
        pdata_bytes: bytes,
    ) -> None:
        self._bits = bits
        self._pdata_addr = pdata_addr
        self._pdata_declared_size = pdata_declared_size
        self._pdata_bytes = pdata_bytes

    def get_arch_info(self) -> dict[str, Any]:
        return {"format": "PE", "bits": self._bits}

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {
                "name": ".pdata",
                "addr": self._pdata_addr,
                "size": self._pdata_declared_size,
            }
        ]

    def read_bytes(self, addr: int, size: int) -> bytes:
        if addr != self._pdata_addr:
            return b""
        return self._pdata_bytes[:size]


class InMemoryPEUnwindBinary(InMemoryPEPdataBinary):
    """Concrete PE double exposing one fixed-address ``.xdata`` section."""

    _XDATA_ADDRESS = 0x5000

    def __init__(self, *, pdata_bytes: bytes, xdata_bytes: bytes) -> None:
        super().__init__(
            bits=64,
            pdata_addr=0x4000,
            pdata_declared_size=len(pdata_bytes),
            pdata_bytes=pdata_bytes,
        )
        self._xdata_bytes = xdata_bytes

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            *super().get_sections(),
            {"name": ".xdata", "addr": self._XDATA_ADDRESS, "size": len(self._xdata_bytes)},
        ]

    def read_bytes(self, addr: int, size: int) -> bytes:
        if addr == self._XDATA_ADDRESS:
            return self._xdata_bytes[:size]
        return super().read_bytes(addr, size)
