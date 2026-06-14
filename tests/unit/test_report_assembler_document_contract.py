"""Contract tests for report document assembly helpers."""

from __future__ import annotations

from r2morph.reporting.report_assembler_document import ReportComputation, build_report_document


def test_report_document_builder_assembles_summary_and_metadata() -> None:
    comp = ReportComputation(
        payload={
            "input_path": "input.bin",
            "arch": "x86_64",
            "bits": 64,
            "format": "elf",
            "functions": 10,
            "working_path": "work.bin",
            "discarded_mutations_detail": [],
            "validation": {"mode": "off"},
            "execution_time_seconds": 1.25,
            "config": {"seed": 7},
            "validation_policy": {"mode": "off"},
            "passes_run": 2,
            "total_mutations": 3,
            "rolled_back_passes": 1,
            "failed_passes": 0,
            "discarded_mutations": 1,
            "requested_validation_mode": "off",
            "validation_mode": "off",
        },
        pass_results={"pass_a": {"status": "ok"}},
        mutations=[],
        aggregate_regions=[{"start": 1}],
        aggregate_changed_bytes=4,
        aggregate_structural_regions=[{"region": 1}],
        degradation_role_counts={"clean": 1},
        pass_timing_summary=[{"pass_name": "pass_a"}],
        diff_digest={"changed_bytes": 4},
        gate_evaluation={"results": {"gate": "ok"}},
        gate_failures={},
        gate_failure_priority=[{"priority": 1}],
        gate_failure_severity_priority=[{"severity": 1}],
        enrichments={
            "symbolic_issue_map": {},
            "symbolic_coverage_map": {},
            "symbolic_severity_map": {},
            "symbolic_status_counts": {},
            "symbolic_status_rows": [],
            "symbolic_status_map": {},
            "observable_mismatch_by_pass": [],
            "observable_mismatch_map": {},
            "observable_mismatch_priority": [],
            "pass_evidence": [],
            "pass_coverage_buckets": {},
            "pass_risk_buckets": {},
            "symbolic_issue_passes": [],
            "symbolic_coverage_by_pass": [],
            "symbolic_severity_by_pass": [],
            "pass_symbolic_summary": {},
        },
        artifacts={
            "pass_support": {},
            "pass_capabilities": {},
            "pass_capability_summary": [],
            "pass_capability_summary_map": {},
            "discarded_mutation_summary": [],
            "discarded_mutation_priority": [],
            "symbolic_overview": {},
            "pass_validation_context": {},
            "validation_role_rows": [],
            "validation_role_map": {},
            "pass_evidence_map": {},
            "pass_region_evidence_map": {},
            "pass_triage_rows": [],
            "pass_triage_map": {},
            "pass_evidence_compact": [],
            "normalized_pass_results": [],
            "report_views": {"sentinel": "views"},
            "structural_evidence": {},
            "validation_adjustments": {},
            "validation_adjustment_rows": [],
            "support_profile": {"support": "full"},
        },
        pass_evidence_priority=[],
    )

    report = build_report_document(comp)

    assert report["schema_version"] == 1
    assert report["input"]["path"] == "input.bin"
    assert report["summary"]["passes_run"] == 2
    assert report["summary"]["changed_bytes"] == 4
    assert report["report_views"] == {"sentinel": "views"}
    assert report["metadata"]["tool"] == "r2morph"
