"""Filtered-summary section compatibility layer.

The actual section builders live in the dedicated gate, risk/coverage, and
degradation modules. This file keeps the public import surface stable.
"""

from __future__ import annotations

from r2morph.reporting.filtered_summary_degradation import _build_filtered_summary_degradation_sections  # noqa: F401
from r2morph.reporting.filtered_summary_discarded import (  # noqa: F401
    _populate_filtered_summary_discarded_sections,
)
from r2morph.reporting.filtered_summary_gate import _build_filtered_summary_gate_sections  # noqa: F401
from r2morph.reporting.filtered_summary_pass_details import (
    _populate_pass_capabilities_and_context,  # noqa: F401
    _populate_pass_evidence,  # noqa: F401
)
from r2morph.reporting.filtered_summary_population import (
    _apply_risk_filters,  # noqa: F401
    _populate_filtered_summary_pass_sections,  # noqa: F401
)
from r2morph.reporting.filtered_summary_risk_coverage import (
    _build_filtered_summary_risk_coverage_sections,  # noqa: F401
)
from r2morph.reporting.filtered_summary_triage import _populate_triage_and_results  # noqa: F401
