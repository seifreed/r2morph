"""Real MutationPass implementation that sleeps before returning.

Not unittest.mock: a concrete MutationPass subclass (the protocol's
real base) whose apply() blocks for a fixed duration so a parallel
batch deterministically exceeds a small executor timeout.
"""

from __future__ import annotations

import time
from typing import Any

from r2morph.mutations.base import MutationPass


class SlowMutationPass(MutationPass):
    def __init__(self, sleep_seconds: float = 1.0) -> None:
        super().__init__(name="slow_test_pass")
        self._sleep_seconds = sleep_seconds

    def apply(self, binary: Any) -> dict[str, Any]:
        time.sleep(self._sleep_seconds)
        return {"success": True, "mutations_applied": 0}
