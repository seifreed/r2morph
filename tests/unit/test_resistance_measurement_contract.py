from __future__ import annotations

from r2morph.analysis.symbolic.resistance_probe import ResistanceMeasurement
from tests.utils.assertions import expect

_STEP_BUDGET = 10


def _measurement(
    *,
    angr_available: bool = True,
    reached_terminal: bool = False,
    budget_exhausted: bool = False,
) -> ResistanceMeasurement:
    return ResistanceMeasurement(
        angr_available=angr_available,
        reached_terminal=reached_terminal,
        steps=0,
        step_budget=_STEP_BUDGET,
        max_active_states=0,
        terminal_states=int(reached_terminal),
        errored_states=0,
        timed_out=False,
        budget_exhausted=budget_exhausted,
        states_truncated=False,
        truncated_states=0,
        execution_time=0.0,
        resistance_score=0.0,
    )


def test_resistance_measurement_classifies_evidence_strength() -> None:
    expect(_measurement(angr_available=False).evidence_status == "unavailable")
    expect(_measurement(reached_terminal=True).evidence_status == "cracked")
    expect(_measurement(budget_exhausted=True).evidence_status == "lower_bound")
    expect(_measurement().evidence_status == "resisted")


def test_resistance_measurement_keeps_release_signoff_human_gated() -> None:
    expect(_measurement(angr_available=False).release_signoff_status == "unavailable")
    expect(_measurement(reached_terminal=True).release_signoff_status == "failed_adversarial_probe")
    expect(_measurement(budget_exhausted=True).release_signoff_status == "pending_human_adversarial_review")
    expect(_measurement().release_signoff_status == "pending_human_adversarial_review")
