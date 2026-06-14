"""Compatibility facade for pass classification and triage helpers."""

from r2morph.reporting.report_pass_classification import (  # noqa: F401
    _has_structural_risk,
    _has_symbolic_risk,
    _is_clean_pass,
    _is_covered_pass,
    _is_risky_pass,
    _is_uncovered_pass,
)
from r2morph.reporting.report_pass_triage_rows import _pass_names_from_triage_rows as _pass_names_from_triage_rows
