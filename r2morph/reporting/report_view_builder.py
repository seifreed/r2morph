"""Report view builder extracted from engine.py."""

from __future__ import annotations

from r2morph.reporting.report_context import ReportViewInputs, ReportViews
from r2morph.reporting.report_view_sections import build_report_views


class ReportViewBuilder:
    """Service adapter over the module-level build_report_views helper."""

    def build_report_views(self, inputs: ReportViewInputs) -> ReportViews:
        return build_report_views(inputs)
