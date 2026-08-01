"""Devirtualization-resistance probe.

Scores how hard it is for a generic symbolic-execution adversary to recover a
function's semantics. The probe drives a bounded symbolic exploration from a
function entry and reports whether the adversary reaches a terminating state -
i.e. recovers the program's exit behaviour - within a fixed step/time budget.

A function the adversary cracks in a handful of steps has low resistance; one
that exhausts the budget without terminating has high resistance. Virtualizing a
function must raise its resistance score - that is the regression this metric
guards. The measurement is generic: it makes no assumption about the function
beyond "run forward from its entry", so it applies to arbitrary binaries (no
sample-specific knowledge).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from r2morph.analysis.symbolic.angr_bridge import ANGR_AVAILABLE, AngrBridge
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)

# Bounded budgets keep the measurement terminating regardless of how divergent the
# target is. They are the adversary's allowance, not a limit on the target.
_DEFAULT_STEP_BUDGET = 500
_DEFAULT_TIMEOUT_SECONDS = 30.0
# Cap on live states carried between steps: symbolic execution of a branchy VM can
# fork; without a cap the probe itself explodes. A solver needing more than this
# many parallel states to progress is, for scoring purposes, not cracking the
# function cheaply.
_MAX_ACTIVE_STATES = 64


@dataclass(frozen=True)
class ResistanceMeasurement:
    """Outcome of one resistance probe run.

    ``resistance_score`` is in ``[0.0, 1.0]``; higher means harder to devirtualize.
    ``reached_terminal`` is the load-bearing signal: True iff the adversary drove
    a state to termination (recovered the exit behaviour) inside the budget.
    """

    angr_available: bool
    reached_terminal: bool
    steps: int
    step_budget: int
    max_active_states: int
    terminal_states: int
    errored_states: int
    timed_out: bool
    execution_time: float
    resistance_score: float


class SymbolicResistanceProbe:
    """A bounded symbolic adversary that scores a function's devirtualization resistance."""

    def __init__(self, binary: Binary) -> None:
        self._binary = binary

    def measure(
        self,
        function_addr: int | None = None,
        *,
        step_budget: int = _DEFAULT_STEP_BUDGET,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> ResistanceMeasurement:
        """Run a bounded symbolic exploration from ``function_addr`` (entry if None).

        Returns a :class:`ResistanceMeasurement`. When angr is unavailable the
        result carries ``angr_available=False`` and a neutral zero score so callers
        can skip rather than crash.
        """
        if not ANGR_AVAILABLE:
            logger.info("Resistance probe skipped: angr backend unavailable")
            return ResistanceMeasurement(
                angr_available=False,
                reached_terminal=False,
                steps=0,
                step_budget=step_budget,
                max_active_states=0,
                terminal_states=0,
                errored_states=0,
                timed_out=False,
                execution_time=0.0,
                resistance_score=0.0,
            )

        bridge = AngrBridge(self._binary)
        project = bridge.angr_project
        start = project.entry if function_addr is None else function_addr
        state = project.factory.blank_state(addr=bridge.resolve_loaded_address(start))
        simgr = project.factory.simulation_manager(state)

        began = time.monotonic()
        steps = 0
        max_active = len(simgr.active)
        timed_out = False
        while simgr.active and steps < step_budget:
            if time.monotonic() - began > timeout:
                timed_out = True
                break
            simgr.step()
            steps += 1
            max_active = max(max_active, len(simgr.active))
            if simgr.deadended:
                # A state terminated: the adversary recovered the exit behaviour.
                break
            if len(simgr.active) > _MAX_ACTIVE_STATES:
                simgr.active = simgr.active[:_MAX_ACTIVE_STATES]
        elapsed = time.monotonic() - began

        reached = len(simgr.deadended) > 0
        # Cracked -> fraction of the budget it cost (low); uncracked -> maximal.
        score = (steps / step_budget) if reached else 1.0
        measurement = ResistanceMeasurement(
            angr_available=True,
            reached_terminal=reached,
            steps=steps,
            step_budget=step_budget,
            max_active_states=max_active,
            terminal_states=len(simgr.deadended),
            errored_states=len(simgr.errored),
            timed_out=timed_out,
            execution_time=elapsed,
            resistance_score=score,
        )
        logger.info(
            "Resistance probe: reached=%s steps=%d/%d score=%.3f time=%.2fs",
            reached,
            steps,
            step_budget,
            score,
            elapsed,
        )
        return measurement
