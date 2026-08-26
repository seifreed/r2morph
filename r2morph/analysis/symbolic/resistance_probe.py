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

``resistance_score = 1.0`` means only "the bounded symbolic adversary did not
recover a terminating state within the given budget" - a LOWER BOUND on
resistance, not a rigorous proof that the function resists symbolic execution.
The bound leaks when the *measurement* runs out of budget (step cap, timeout) or
drops the very state that was about to terminate while capping live states. Those
runs carry ``budget_exhausted=True`` (and ``states_truncated=True`` if the cap
actually dropped states) so a caller can tell an honest 1.0 apart from a
budget-limited one. Pair this dynamic signal with the static
:class:`~r2morph.analysis.symbolic.structural_resistance.StructuralResistanceProbe`
in this package for a gradient view of hardening progress.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

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


def _path_constraint_count(state: Any) -> int:
    """Accumulated path constraints on a state - a proxy for how many forks it took."""
    return len(state.solver.constraints)


def _cap_live_states(states: list[Any], cap: int) -> tuple[list[Any], int]:
    """Keep the ``cap`` live states likeliest to terminate; report how many are dropped.

    Capping the live set is what keeps the probe from exploding on a branchy VM.
    Dropping an arbitrary prefix can discard the very state about to reach a clean
    exit, inflating resistance. Instead the states are ranked by accumulated path
    constraints (fewer constraints means a straighter path, likelier to terminate
    next) and the least-constrained ``cap`` are kept. Truncation is still lossy, so
    the caller flags any run where states were dropped.
    """
    ranked = sorted(states, key=_path_constraint_count)
    return ranked[:cap], max(len(states) - cap, 0)


@dataclass(frozen=True)
class ResistanceMeasurement:
    """Outcome of one resistance probe run.

    ``resistance_score`` is in ``[0.0, 1.0]``; higher means harder to devirtualize.
    ``reached_terminal`` is the load-bearing signal: True iff the adversary drove
    a state to termination (recovered the exit behaviour) inside the budget.

    ``budget_exhausted`` guards against a false-resistant verdict: it is True when
    the run stopped because it hit ``step_budget``, timed out, or truncated the
    live-state set - i.e. it did NOT explore to natural completion. When
    ``reached_terminal`` is False but ``budget_exhausted`` is True, the ``1.0``
    score is a LOWER BOUND on resistance, not proof the function resisted the
    adversary. ``states_truncated`` is True when the live-state cap actually
    dropped states (which may have discarded the state that was about to
    terminate), and ``truncated_states`` counts how many were dropped in total.
    """

    angr_available: bool
    reached_terminal: bool
    steps: int
    step_budget: int
    max_active_states: int
    terminal_states: int
    errored_states: int
    timed_out: bool
    budget_exhausted: bool
    states_truncated: bool
    truncated_states: int
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
                budget_exhausted=False,
                states_truncated=False,
                truncated_states=0,
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
        dropped = 0
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
                kept, dropped_now = _cap_live_states(simgr.active, _MAX_ACTIVE_STATES)
                simgr.active = kept
                dropped += dropped_now
        elapsed = time.monotonic() - began

        reached = len(simgr.deadended) > 0
        states_truncated = dropped > 0
        # The run failed to explore to natural completion when a budget bound cut it
        # short or the live-state cap discarded states - so an uncracked verdict is a
        # lower bound, not proof of resistance.
        unconstrained_states = bool(getattr(simgr, "unconstrained", ()))
        budget_exhausted = (
            timed_out
            or states_truncated
            or (not reached and (steps >= step_budget or bool(simgr.active) or unconstrained_states))
        )
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
            budget_exhausted=budget_exhausted,
            states_truncated=states_truncated,
            truncated_states=dropped,
            execution_time=elapsed,
            resistance_score=score,
        )
        logger.info(
            "Resistance probe: reached=%s steps=%d/%d score=%.3f " "budget_exhausted=%s truncated=%d time=%.2fs",
            reached,
            steps,
            step_budget,
            score,
            budget_exhausted,
            dropped,
            elapsed,
        )
        return measurement
