"""Lock the observable mismatch helper module boundary."""

from __future__ import annotations

from r2morph.core import report_helpers_evidence as evidence_mod
from r2morph.core import report_helpers_observables as observables_mod


def test_observable_mismatch_helpers_are_defined_on_canonical_module() -> None:
    assert observables_mod._summarize_observable_mismatches_by_pass is not None
    assert observables_mod._build_observable_mismatch_map is not None
    assert observables_mod._build_observable_mismatch_priority is not None


def test_evidence_facade_reexports_observable_helpers() -> None:
    assert (
        evidence_mod._summarize_observable_mismatches_by_pass
        is observables_mod._summarize_observable_mismatches_by_pass
    )
    assert (
        evidence_mod._build_observable_mismatch_map
        is observables_mod._build_observable_mismatch_map
    )
    assert (
        evidence_mod._build_observable_mismatch_priority
        is observables_mod._build_observable_mismatch_priority
    )
