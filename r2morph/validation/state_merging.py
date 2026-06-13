"""State-merging helpers for extended semantic validation."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.analysis.cfg import ControlFlowGraph

angr: Any
try:
    import angr

    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    angr = None

logger = logging.getLogger(__name__)


class ImprovedStateMerging:
    """Advanced state merging for symbolic execution."""

    def __init__(self, k_limit: int = 3) -> None:
        """Initialize state merging."""
        self.k_limit = k_limit
        self._merge_points: dict[int, list[Any]] = {}

    def find_merge_points(self, cfg: ControlFlowGraph) -> list[int]:
        """Find optimal merge points in a CFG."""
        merge_points = []

        cfg.compute_dominators()

        for addr, block in cfg.blocks.items():
            if len(block.predecessors) > 1:
                merge_points.append(addr)

        loops = cfg.find_loops()
        for from_addr, to_addr in loops:
            if to_addr not in merge_points:
                merge_points.append(to_addr)

        return list(set(merge_points))

    def should_merge(self, state1: Any, state2: Any) -> bool:
        """Determine if two states should be merged."""
        if not ANGR_AVAILABLE:
            return False

        try:
            if state1.addr != state2.addr:
                return False

            if hasattr(state1, "history") and hasattr(state2, "history"):
                if state1.history.depth > 50 or state2.history.depth > 50:
                    return True

            if len(state1.solver.constraints) > 20 or len(state2.solver.constraints) > 20:
                return True

            return False

        except Exception:
            return False

    def merge_states(self, states: list[Any]) -> Any | None:
        """Merge multiple states into one."""
        if not ANGR_AVAILABLE or not states:
            return None

        if len(states) == 1:
            return states[0]

        try:
            merged = states[0]
            for state in states[1:]:
                if self.should_merge(merged, state):
                    merged, _ = merged.merge(state)
                else:
                    return None

            return merged

        except Exception as exc:
            logger.debug("State merge failed: %s", exc)
            return None

    def get_merge_statistics(self) -> dict[str, Any]:
        """Get statistics about merge points."""
        return {
            "merge_points": len(self._merge_points),
            "states_at_merge_points": {addr: len(states) for addr, states in self._merge_points.items()},
        }
