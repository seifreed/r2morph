"""A real ReportViewBuilderProtocol double that records calls."""

from __future__ import annotations

from typing import Any


class _RecordedViews:
    """Stand-in for ReportViews; only to_dict() is consumed by the engine."""

    def to_dict(self) -> dict[str, Any]:
        return {"sentinel": "report_views"}


class RecordingReportViewBuilder:
    """Records every build_report_views call; returns a sentinel view object."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def build_report_views(self, **kwargs: Any) -> _RecordedViews:
        self.calls.append(kwargs)
        return _RecordedViews()
