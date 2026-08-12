"""Lock the observable mismatch helper module boundary."""

from __future__ import annotations

from r2morph.core import report_helpers_observables as observables_mod


def test_observable_mismatch_helpers_are_defined_on_canonical_module() -> None:
    assert observables_mod._summarize_observable_mismatches_by_pass is not None
    assert observables_mod._build_observable_mismatch_map is not None
    assert observables_mod._build_observable_mismatch_priority is not None
