"""Public CLI rendering API for report output.

This module is a compatibility facade over the split rendering modules.
Structured rendering lives in report_rendering_tables, status/flow text in
report_rendering_text_sections, and shared console/table primitives in
report_rendering_primitives.
"""

from __future__ import annotations

from r2morph.reporting.report_rendering_flow_text_sections import (
    render_gate_evaluation_sections,
    render_general_only_pass_sections,
    render_general_report_sections,
)
from r2morph.reporting.report_rendering_pass_tables import (
    render_only_pass_sections,
    render_pass_capabilities,
    render_pass_validation_contexts,
)
from r2morph.reporting.report_rendering_primitives import CONSOLE, create_table
from r2morph.reporting.report_rendering_summary_tables import (
    render_summary_table,
    render_validation_context_table,
)
from r2morph.reporting.report_rendering_tables import (
    render_degradation_sections,
    render_gate_sections,
    render_only_mismatches_sections,
    render_symbolic_sections,
)
from r2morph.reporting.report_rendering_text_sections import (
    render_mismatch_summary_sections,
    render_report_filter_messages,
)

__all__ = [
    "CONSOLE",
    "create_table",
    "render_pass_capabilities",
    "render_pass_validation_contexts",
    "render_symbolic_sections",
    "render_gate_sections",
    "render_degradation_sections",
    "render_only_mismatches_sections",
    "render_only_pass_sections",
    "render_report_filter_messages",
    "render_summary_table",
    "render_gate_evaluation_sections",
    "render_general_report_sections",
    "render_general_only_pass_sections",
    "render_mismatch_summary_sections",
    "render_validation_context_table",
]
