"""In-memory Binary double for type-inference tests.

A real (non-mock) implementation of the Binary surface that
``TypeInference.propagate_interprocedural_types`` consumes: architecture
metadata, a function list, and per-function disassembly. ``failing_addrs``
makes ``get_function_disasm`` raise for chosen addresses so the inference
loop's error path can be exercised without mocking.
"""

from __future__ import annotations

from typing import Any


class InMemoryTypedBinary:
    """Controlled stand-in for ``r2morph.core.binary.Binary``."""

    def __init__(
        self,
        *,
        arch: str = "x86_64",
        bits: int = 64,
        functions: list[dict[str, Any]] | None = None,
        disasm_by_addr: dict[int, list[dict[str, Any]]] | None = None,
        failing_addrs: set[int] | None = None,
    ) -> None:
        self._arch = arch
        self._bits = bits
        self._functions = functions or []
        self._disasm_by_addr = disasm_by_addr or {}
        self._failing_addrs = failing_addrs or set()

    def get_arch_info(self) -> dict[str, Any]:
        return {"arch": self._arch, "bits": self._bits}

    def get_functions(self) -> list[dict[str, Any]]:
        return list(self._functions)

    def get_function_disasm(self, func_addr: int) -> list[dict[str, Any]]:
        if func_addr in self._failing_addrs:
            raise OSError(f"disassembly unavailable for {func_addr:#x}")
        return self._disasm_by_addr.get(func_addr, [])
