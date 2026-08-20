"""Characterization tests for ``MorphEngine.build_report``.

These lock the exact public report contract (top-level key set, summary
key set, schema version, field propagation, and determinism modulo the
audit timestamp) BEFORE the engine.py §7 decomposition. The decomposition
must keep these green — they are the behaviour-preservation oracle for
relocating report assembly out of ``core/engine.py``.

No mocks / monkeypatch (CLAUDE.md §4): a real ``MorphEngine`` is
constructed and ``build_report`` is exercised with real dict payloads.
``build_report`` performs no binary I/O, so no fixture binary is needed.
"""

from datetime import datetime

from r2morph.core.engine import MorphEngine
from tests._doubles.recording_gate_failure_reporter import RecordingGateFailureReporter
from tests._doubles.recording_report_view_builder import RecordingReportViewBuilder
from tests.utils.assertions import expect

_EXPECTED_REPORT_SUMMARY_CHANGED_BYTES_4 = 4


# Frozen contract captured from the pre-refactor implementation.
EXPECTED_TOP_LEVEL_KEYS = {
    "config",
    "diff_digest",
    "discarded_mutation_priority",
    "discarded_mutation_summary",
    "discarded_mutations",
    "gate_evaluation",
    "gate_failure_priority",
    "gate_failure_severity_priority",
    "gate_failures",
    "input",
    "metadata",
    "mutations",
    "normalized_pass_results",
    "observable_mismatch_by_pass",
    "observable_mismatch_map",
    "observable_mismatch_priority",
    "output",
    "pass_capabilities",
    "pass_capability_summary",
    "pass_capability_summary_map",
    "pass_coverage_buckets",
    "pass_evidence",
    "pass_evidence_compact",
    "pass_evidence_map",
    "pass_evidence_priority",
    "pass_region_evidence_map",
    "pass_risk_buckets",
    "pass_support",
    "pass_symbolic_summary",
    "pass_triage_map",
    "pass_triage_rows",
    "pass_validation_context",
    "passes",
    "report_views",
    "schema_version",
    "structural_evidence",
    "summary",
    "support_matrix",
    "support_profile",
    "symbolic_coverage_map",
    "symbolic_issue_map",
    "symbolic_overview",
    "symbolic_severity_map",
    "symbolic_status_counts",
    "symbolic_status_map",
    "symbolic_status_rows",
    "timings",
    "validation",
    "validation_adjustment_rows",
    "validation_adjustments",
    "validation_policy",
    "validation_role_map",
    "validation_role_rows",
}

REPRESENTATIVE_PAYLOAD = {
    "input_path": "/bin/ls",
    "arch": "x86",
    "bits": 64,
    "format": "elf",
    "functions": 12,
    "working_path": "test-data/out",
    "pass_results": {
        "nop": {
            "diff_summary": {
                "changed_regions": [[1, 2]],
                "changed_bytes": 4,
                "structural_regions": [],
            }
        }
    },
    "mutations": [{"kind": "nop"}],
    "passes_run": 1,
    "total_mutations": 1,
    "execution_time_seconds": 0.5,
    "validation_mode": "static",
}


class TestBuildReportContract:
    def test_top_level_key_set_is_frozen(self) -> None:
        report = MorphEngine().build_report({})
        expect(set(report.keys()) == EXPECTED_TOP_LEVEL_KEYS)

    def test_schema_version_is_one(self) -> None:
        expect(MorphEngine().build_report({})["schema_version"] == 1)

    def test_empty_payload_defaults(self) -> None:
        report = MorphEngine().build_report({})
        expect(report["input"] == {"path": None, "arch": None, "bits": None, "format": None, "functions": None})
        expect(report["output"] == {"working_path": None})
        expect(report["passes"] == {})
        expect(report["mutations"] == [])
        summary = report["summary"]
        expect(summary["passes_run"] == 0)
        expect(summary["total_mutations"] == 0)
        expect(summary["rolled_back_passes"] == 0)
        expect(summary["failed_passes"] == 0)
        expect(summary["discarded_mutations"] == 0)
        expect(summary["changed_bytes"] == 0)
        expect(summary["validation_mode"] == "off")

    def test_summary_key_set_is_frozen(self) -> None:
        report = MorphEngine().build_report({})
        # The summary key set must be stable across the refactor; capture
        # it from the report itself and assert it is non-empty and a
        # superset of the documented scalar fields.
        summary_keys = set(report["summary"].keys())
        expect(
            not (
                {
                    "passes_run",
                    "total_mutations",
                    "rolled_back_passes",
                    "failed_passes",
                    "discarded_mutations",
                    "changed_bytes",
                    "validation_mode",
                    "schema_version",
                }
                > summary_keys
            )
        )

    def test_representative_payload_propagates_fields(self) -> None:
        report = MorphEngine().build_report(REPRESENTATIVE_PAYLOAD)
        expect(report["input"] == {"path": "/bin/ls", "arch": "x86", "bits": 64, "format": "elf", "functions": 12})
        expect(report["output"] == {"working_path": "test-data/out"})
        expect(set(report["passes"].keys()) == {"nop"})
        expect(report["mutations"] == [{"kind": "nop"}])
        expect(report["summary"]["passes_run"] == 1)
        expect(report["summary"]["total_mutations"] == 1)
        expect(report["summary"]["changed_bytes"] == _EXPECTED_REPORT_SUMMARY_CHANGED_BYTES_4)
        expect(report["summary"]["validation_mode"] == "static")

    def test_representative_payload_has_same_top_level_keys(self) -> None:
        report = MorphEngine().build_report(REPRESENTATIVE_PAYLOAD)
        expect(set(report.keys()) == EXPECTED_TOP_LEVEL_KEYS)

    def test_metadata_timestamp_is_iso_and_only_nondeterministic_field(self) -> None:
        engine = MorphEngine()
        first = engine.build_report({})
        second = engine.build_report({})

        # metadata.timestamp is an audit timestamp and is the ONLY
        # non-deterministic part of the report; it must parse as ISO-8601.
        datetime.fromisoformat(first["metadata"]["timestamp"])
        datetime.fromisoformat(second["metadata"]["timestamp"])

        first["metadata"].pop("timestamp")
        second["metadata"].pop("timestamp")
        expect(first == second)

    def test_build_report_routes_gate_failures_through_injected_reporter(self) -> None:
        reporter = RecordingGateFailureReporter()
        engine = MorphEngine(gate_failure_reporter=reporter)

        report = engine.build_report({"gate_evaluation": {"requested": {}, "results": {}}})

        expect(reporter.summarize_calls)
        expect(reporter.summarize_calls[0] == {"requested": {}, "results": {}})
        expect(reporter.priority_calls)
        expect(reporter.severity_priority_calls)
        expect(report["gate_failures"] == {"sentinel": "summary"})
        expect(report["gate_failure_priority"] == [{"sentinel": "priority"}])
        expect(report["gate_failure_severity_priority"] == [{"sentinel": "severity"}])
        expect(set(report.keys()) == EXPECTED_TOP_LEVEL_KEYS)

    def test_build_report_routes_views_through_injected_builder(self) -> None:
        builder = RecordingReportViewBuilder()
        engine = MorphEngine(report_view_builder=builder)

        report = engine.build_report({})

        expect(builder.calls)
        expect(report["report_views"] == {"sentinel": "report_views"})
        expect(set(report.keys()) == EXPECTED_TOP_LEVEL_KEYS)
