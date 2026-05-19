"""Real DisassemblerInterface double that fails after a successful open.

Not unittest.mock: a concrete object whose open()/cmdj() succeed (so
Binary.open assigns it to self.r2) but whose cmd() raises, modelling a
radare2 connection that breaks during post-spawn configuration (e.g.
the low-memory `e bin.cache=false` commands). It records whether quit()
was called so a leaked-vs-released connection is observable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class FailingPostSpawnDisassembler:
    def __init__(self) -> None:
        self.quit_called = False
        self.opened = False

    def open(self, path: Path, flags: list[str]) -> None:
        self.opened = True

    def cmdj(self, command: str) -> dict[str, Any]:
        return {}

    def cmd(self, command: str) -> str:
        raise BrokenPipeError(f"r2 pipe broke during post-spawn config: {command!r}")

    def quit(self) -> None:
        self.quit_called = True
