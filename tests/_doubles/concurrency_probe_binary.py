"""Real named doubles that observe concurrent radare2 access.

Not unittest.mock: ``_ConcurrencyProbeR2`` is a concrete object whose
``cmd``/``cmdj`` record the peak number of threads inside it at once, and
``ProbeSimplificationPass`` is a real ``SimplificationPass`` subclass that
drives that r2. Together they make "the parallel path must not drive the
one shared r2pipe from more than one thread at a time" an observable,
deterministic assertion.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from r2morph.devirtualization.iterative_simplifier import SimplificationPass

# Long enough that three workers entering an unsynchronized r2 reliably
# overlap; short enough to keep the test fast.
_OVERLAP_WINDOW_SECONDS = 0.02


class _ConcurrencyProbeR2:
    """Records the maximum number of threads simultaneously issuing a command."""

    def __init__(self) -> None:
        self._active = 0
        self._counter_lock = threading.Lock()
        self.max_concurrency = 0
        self.call_count = 0

    def _enter(self) -> None:
        with self._counter_lock:
            self._active += 1
            self.call_count += 1
            self.max_concurrency = max(self.max_concurrency, self._active)

    def _leave(self) -> None:
        with self._counter_lock:
            self._active -= 1

    def cmd(self, command: str) -> str:
        self._enter()
        time.sleep(_OVERLAP_WINDOW_SECONDS)
        self._leave()
        return ""

    def cmdj(self, command: str) -> list[Any]:
        self.cmd(command)
        return []


class ConcurrencyProbeBinary:
    """Minimal binary whose ``.r2`` is a concurrency-recording probe."""

    def __init__(self) -> None:
        self.r2 = _ConcurrencyProbeR2()


class ProbeSimplificationPass(SimplificationPass):
    """A real pass that drives the shared binary's r2, like the production passes."""

    def __init__(self, name: str) -> None:
        self._name = name

    def apply(self, binary: Any, context: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        binary.r2.cmd(f"pdf @ {self._name}")
        return False, context

    def get_name(self) -> str:
        return self._name
