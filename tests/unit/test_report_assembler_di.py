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
from tests.utils.assertions import expect


def test_report_assembler_routes_through_injected_collaborators() -> None:
    gate = RecordingGateFailureReporter()
    views = RecordingReportViewBuilder()
    assembler = ReportAssembler(gate, views)

    report = assembler.assemble_report({}, pipeline_passes=[], last_result=None)

    expect(gate.priority_calls)
    expect(gate.severity_priority_calls)
    expect(views.calls)
    expect(report["schema_version"] == 1)
    expect(report["report_views"] == {"sentinel": "report_views"})


def test_morphengine_build_report_delegates_to_injected_report_builder() -> None:
    recorder = RecordingReportAssembler()
    engine = MorphEngine(report_builder=recorder)

    out = engine.build_report({"marker": 1})

    expect(out == {"sentinel": "report"})
    expect(len(recorder.calls) == 1)
    call = recorder.calls[0]
    expect(call["result"] == {"marker": 1})
    expect(call["pipeline_passes"] == [])
    expect(not (call["last_result"] is not None))
