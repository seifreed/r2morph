"""Slice 5.3 DI seams: ReportAssembler internals + the MorphEngine seam.

No mocks (CLAUDE.md §4): real ReportAssembler / MorphEngine with real
recording doubles from tests/_doubles/.
"""

from __future__ import annotations

from r2morph.core.engine import MorphEngine
from r2morph.reporting.report_assembler import ReportAssembler
from tests._doubles.recording_gate_failure_reporter import RecordingGateFailureReporter
from tests._doubles.recording_report_assembler import RecordingReportAssembler
from tests._doubles.recording_report_view_builder import RecordingReportViewBuilder


def test_report_assembler_routes_through_injected_collaborators() -> None:
    gate = RecordingGateFailureReporter()
    views = RecordingReportViewBuilder()
    assembler = ReportAssembler(gate, views)

    report = assembler.assemble_report({}, pipeline_passes=[], last_result=None)

    assert gate.priority_calls
    assert gate.severity_priority_calls
    assert views.calls
    assert report["schema_version"] == 1
    assert report["report_views"] == {"sentinel": "report_views"}


def test_morphengine_build_report_delegates_to_injected_report_builder() -> None:
    recorder = RecordingReportAssembler()
    engine = MorphEngine(report_builder=recorder)

    out = engine.build_report({"marker": 1})

    assert out == {"sentinel": "report"}
    assert len(recorder.calls) == 1
    call = recorder.calls[0]
    assert call["result"] == {"marker": 1}
    assert call["pipeline_passes"] == []
    assert call["last_result"] is None
