"""A real ReportBuilderProtocol double that records assemble_report calls."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


class RecordingReportAssembler:
    """Records every assemble_report call; returns a fixed sentinel report."""

    SENTINEL: dict[str, Any] = {"sentinel": "report"}

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def assemble_report(
        self,
        result: dict[str, Any] | None,
        *,
        pipeline_passes: Sequence[Any],
        last_result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "result": result,
                "pipeline_passes": list(pipeline_passes),
                "last_result": last_result,
            }
        )
        return dict(self.SENTINEL)
