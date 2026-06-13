"""Contract tests for report artifact assembly helpers."""

from __future__ import annotations

from r2morph.reporting.report_assembler_artifacts import build_report_artifacts
from tests._doubles.recording_report_view_builder import RecordingReportViewBuilder


def test_report_artifacts_builder_routes_through_view_builder() -> None:
    views = RecordingReportViewBuilder()
    artifacts = build_report_artifacts(
        payload={
            "format": "elf",
            "arch": "x86",
            "bits": 64,
            "validation_mode": "off",
        },
        pass_results={},
        enrichments={
            "pass_evidence": [],
            "pass_risk_buckets": {"clean": [], "covered": [], "uncovered": []},
            "pass_coverage_buckets": {"clean_only": [], "covered": [], "uncovered": []},
            "pass_triage_rows": [],
            "normalized_pass_results": [],
            "pass_symbolic_summary": {},
            "observable_mismatch_priority": [],
            "observable_mismatch_map": {},
            "symbolic_severity_by_pass": [],
            "symbolic_coverage_by_pass": [],
            "symbolic_status_counts": {},
        },
        aggregate_structural_regions=[],
        gate_failures={},
        gate_failure_priority=[{"sentinel": "priority"}],
        gate_failure_severity_priority=[{"sentinel": "severity"}],
        pipeline_passes=[],
        report_view_builder=views,
    )

    assert views.calls
    assert artifacts["report_views"] == {"sentinel": "report_views"}
