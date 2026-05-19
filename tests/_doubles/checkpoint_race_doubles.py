"""Real doubles exposing the checkpoint-vs-apply race in
ParallelMutationEngine.

Not unittest.mock: ``BinaryAccessRecorder`` is a thread-safe peak-active
counter, ``CriticalSectionPass`` is a real MutationPassProtocol-shaped
pass whose apply() occupies the binary, and ``ProbeBinary.path`` is a
property whose getter (read by engine._save_checkpoint's shutil.copy2)
also occupies the binary for a window. Copying the real (whole) binary
in _save_checkpoint is not instantaneous, so modelling it as a window
makes "snapshot and mutation must be mutually exclusive" an observable,
deterministic peak-concurrency assertion.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

_BINARY_BUSY_WINDOW_SECONDS = 0.15


class BinaryAccessRecorder:
    def __init__(self) -> None:
        self._active = 0
        self._mutex = threading.Lock()
        self.max_active = 0

    def _occupy(self) -> None:
        with self._mutex:
            self._active += 1
            self.max_active = max(self.max_active, self._active)
        time.sleep(_BINARY_BUSY_WINDOW_SECONDS)
        with self._mutex:
            self._active -= 1


class CriticalSectionPass:
    def __init__(self, name: str, recorder: BinaryAccessRecorder) -> None:
        self.name = name
        self.enabled = True
        self.config: dict[str, Any] = {}
        self._recorder = recorder

    def apply(self, binary: Any) -> dict[str, Any]:
        self._recorder._occupy()
        return {"success": True, "mutations_applied": 0}


class ProbeBinary:
    def __init__(self, real_path: Path, recorder: BinaryAccessRecorder) -> None:
        self._real_path = real_path
        self._recorder = recorder

    @property
    def path(self) -> Path:
        # _save_checkpoint reads this to shutil.copy2 the whole binary;
        # model that copy as occupying the binary for a window.
        self._recorder._occupy()
        return self._real_path
