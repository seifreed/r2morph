"""Real doubles that make ParallelMutationEngine's in-process binary
serialization observable.

Not unittest.mock: ``ConcurrencyRecorder`` is a thread-safe peak-active
counter, ``RecordingMutationPass`` is a real MutationPassProtocol-shaped
pass whose apply() records how many pass-workers touch the shared binary
at once, and ``PathOnlyBinary`` is a minimal binary exposing the .path
BinaryFileLock needs. Together they turn "only one pass may mutate the
shared Binary at a time" into a deterministic assertion.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

# Long enough that two unsynchronized workers reliably overlap.
_OVERLAP_WINDOW_SECONDS = 0.05


class ConcurrencyRecorder:
    def __init__(self) -> None:
        self._active = 0
        self._mutex = threading.Lock()
        self.max_active = 0

    def __enter__(self) -> "ConcurrencyRecorder":
        with self._mutex:
            self._active += 1
            self.max_active = max(self.max_active, self._active)
        return self

    def __exit__(self, *exc: Any) -> None:
        with self._mutex:
            self._active -= 1


class RecordingMutationPass:
    def __init__(self, name: str, recorder: ConcurrencyRecorder) -> None:
        self.name = name
        self.enabled = True
        self.config: dict[str, Any] = {}
        self._recorder = recorder

    def apply(self, binary: Any) -> dict[str, Any]:
        with self._recorder:
            time.sleep(_OVERLAP_WINDOW_SECONDS)
        return {"success": True, "mutations_applied": 0}


class PathOnlyBinary:
    def __init__(self, path: Path) -> None:
        self.path = path
