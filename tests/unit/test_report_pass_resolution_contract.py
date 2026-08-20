"""Contract tests for pass-level report resolution helpers."""

from __future__ import annotations

from r2morph.reporting.report_pass_resolution import resolve_only_pass_view
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY


def test_resolve_only_pass_view_uses_summary_fallbacks() -> None:
    summary = {
        "report_views": {"only_pass": {"alpha": {"normalized": {"severity": "high", "role": "requested-mode"}}}},
        "pass_validation_context": {},
        "pass_region_evidence_map": {},
        "normalized_pass_results": [],
    }
    filtered_summary = {"pass_symbolic_summary": {}, "pass_evidence": [], "pass_validation_context": {}}
    symbolic, evidence, context, region = resolve_only_pass_view(
        summary=summary,
        filtered_summary=filtered_summary,
        pass_results={"alpha": {}},
        **{MUTATION_NAME_KEY: "alpha"},
    )

    expect(symbolic is not None)
    expect(symbolic["severity"] == "high")
    expect(evidence is not None)
    expect(context is not None)
    expect(context["role"] == "requested-mode")
    expect(not (region is not None))
