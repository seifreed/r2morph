"""A real Binary-shaped double whose r2.cmd returns scripted output.

Not unittest.mock: a concrete object whose ``r2.cmd`` dispatches on the
command prefix to caller-supplied canned strings (including ``""`` and
``None``), so code that parses raw r2 output can be exercised against
degenerate output without monkeypatching.
"""

from __future__ import annotations

from typing import Any


class _ScriptedR2:
    def __init__(self, responses: dict[str, str | None]) -> None:
        self._responses = responses

    def cmd(self, command: str) -> str | None:
        for prefix, value in self._responses.items():
            if command.startswith(prefix):
                return value
        return ""


class ScriptedR2Binary:
    """Minimal binary exposing ``.r2.cmd`` with prefix-scripted answers.

    Optionally exposes ``get_arch_info()`` and a recording ``write_bytes``
    for code paths (e.g. relocation manager) that need them.
    """

    def __init__(
        self,
        responses: dict[str, str | None],
        arch_info: dict[str, Any] | None = None,
    ) -> None:
        self.r2 = _ScriptedR2(responses)
        self._arch_info = arch_info if arch_info is not None else {"bits": 64}
        self.writes: list[tuple[int, bytes]] = []

    def get_arch_info(self) -> dict[str, Any]:
        return self._arch_info

    def write_bytes(self, address: int, data: bytes) -> bool:
        self.writes.append((address, data))
        return True
