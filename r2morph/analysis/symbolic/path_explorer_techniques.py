"""Exploration techniques used by the symbolic path explorer."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import angr
    from angr.exploration_techniques import ExplorationTechnique
else:
    try:
        import angr
        from angr.exploration_techniques import ExplorationTechnique
    except ImportError:
        angr = None

        class ExplorationTechnique:
            """Fallback ExplorationTechnique when angr is not installed."""

            def __init__(self) -> None:
                pass

logger = logging.getLogger(__name__)

ANGR_AVAILABLE = angr is not None


class VMHandlerDetectionTechnique(ExplorationTechnique):
    """Exploration technique specialized for VM handler detection."""

    def __init__(self) -> None:
        super().__init__()
        self.handler_patterns: set[int] = set()
        self.switch_tables: dict[int, list[int]] = {}

    def step(self, simgr: Any, stash: str = "active", **kwargs: Any) -> Any:
        if not ANGR_AVAILABLE:
            return simgr

        if stash in simgr.stashes:
            states = simgr.stashes[stash]
            scored_states = []

            for state in states:
                score = self._score_vm_likelihood(state)
                scored_states.append((score, state))

            scored_states.sort(key=lambda x: x[0], reverse=True)
            simgr.stashes[stash] = [state for _, state in scored_states[:10]]

        return simgr

    def _score_vm_likelihood(self, state: Any) -> float:
        score = 0.0

        try:
            if state.solver.symbolic(state.regs.rip):
                score += 2.0

            if hasattr(state, "history") and state.history.jump_kind == "Ijk_Boring":
                score += 1.0

            if len(state.history.mem_reads.hardcopy) > 5:
                score += 1.5

            if state.history.depth > 50:
                score -= 1.0

        except Exception as e:
            logger.debug(f"Error scoring VM likelihood: {e}")

        return score


class OpaquePredicateDetectionTechnique(ExplorationTechnique):
    """Exploration technique for detecting opaque predicates."""

    def __init__(self) -> None:
        super().__init__()
        self.branch_outcomes: dict[int, list[bool]] = {}
        self.opaque_candidates: set[int] = set()

    def step(self, simgr: Any, stash: str = "active", **kwargs: Any) -> Any:
        if not ANGR_AVAILABLE:
            return simgr

        if stash in simgr.stashes:
            for state in simgr.stashes[stash]:
                self._track_branch_outcomes(state)

        return simgr

    def _track_branch_outcomes(self, state: Any) -> None:
        try:
            if hasattr(state, "history") and state.history.jump_kind == "Ijk_Conditional":
                branch_addr = state.history.addr

                if branch_addr not in self.branch_outcomes:
                    self.branch_outcomes[branch_addr] = []

                taken = state.history.jumpkind == "Ijk_Conditional"
                self.branch_outcomes[branch_addr].append(taken)

                outcomes = self.branch_outcomes[branch_addr]
                if len(outcomes) >= 5 and len(set(outcomes)) == 1:
                    self.opaque_candidates.add(branch_addr)
                    logger.info(f"Potential opaque predicate at 0x{branch_addr:x}")

        except Exception as e:
            logger.debug(f"Error tracking branch outcomes: {e}")
