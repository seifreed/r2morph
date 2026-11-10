"""
Integration tests for CLI.
"""

import importlib
import importlib.util
import json
import sys

import pytest

from r2morph import MorphEngine
from r2morph.core.engine_run import EngineRunOptions
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.integration.cli_test_support import CLIIntegrationBase, _ReportFixturePass
from tests.utils.assertions import expect, expect_all
from tests.utils.field_names import MUTATION_NAME_KEY, ONLY_MUTATION_KEY
from tests.utils.process import run_command

_EXPECTED_FAILURES_COUNT_NOPINSERTION_NOT_REQUESTED_EXP_2 = 2
_EXPECTED_PRIORITY_0_FAILURE_COUNT_2 = 2
_EXPECTED_RESULT_RETURNCODE_2 = 2
_EXPECTED_RESULT_RETURNCODE_2_2 = 2


# Check if typer is available
try:
    importlib_util = importlib.import_module("importlib.util")

    TYPER_AVAILABLE = importlib_util.find_spec("typer") is not None
except ImportError:
    TYPER_AVAILABLE = False


@pytest.mark.skipif(not TYPER_AVAILABLE, reason="typer not installed")
class TestCLI(CLIIntegrationBase):
    """CLI integration coverage for one cohesive command workflow."""

    def test_engine_generated_report_persists_pass_buckets(self, deterministic_register_elf, tmp_path):
        """Test engine-generated reports persist risk/coverage buckets in summary."""
        report = tmp_path / "engine_buckets.report.json"

        with MorphEngine(config={"seed": 1337}) as engine:
            engine.load_binary(deterministic_register_elf).analyze()
            engine.add_mutation(
                RegisterSubstitutionPass(
                    config={
                        "probability": 1.0,
                        "max_substitutions_per_function": 6,
                        "seed": 1337,
                    }
                )
            )
            engine.run(EngineRunOptions(validation_mode="symbolic", seed=1337, report_path=report))

        payload = json.loads(report.read_text(encoding="utf-8"))
        expect_all(
            not ("pass_risk_buckets" not in payload),
            not ("pass_coverage_buckets" not in payload),
            not ("pass_risk_buckets" not in payload["summary"]),
            not ("pass_coverage_buckets" not in payload["summary"]),
            not ("pass_capabilities" not in payload["summary"]),
            not ("pass_evidence_map" not in payload["summary"]),
            not ("pass_evidence_priority" not in payload["summary"]),
            not ("pass_triage_rows" not in payload["summary"]),
            not ("pass_triage_map" not in payload["summary"]),
            not ("pass_evidence_compact" not in payload["summary"]),
            not ("normalized_pass_results" not in payload["summary"]),
            not ("report_views" not in payload["summary"]),
            not ("schema_version" not in payload),
            not ("schema_version" not in payload["summary"]),
            not ("validation_adjustment_rows" not in payload["summary"]),
            not ("pass_capability_summary" not in payload["summary"]),
            not ("pass_capability_summary_map" not in payload["summary"]),
            not ("validation_role_rows" not in payload["summary"]),
            not ("validation_role_map" not in payload["summary"]),
            not ("validation_adjustments" not in payload["summary"]),
            not ("symbolic_issue_map" not in payload["summary"]),
            not ("symbolic_coverage_map" not in payload["summary"]),
            not ("symbolic_severity_map" not in payload["summary"]),
            not ("symbolic_status_counts" not in payload["summary"]),
            not ("symbolic_status_rows" not in payload["summary"]),
            not ("symbolic_status_map" not in payload["summary"]),
            not ("symbolic_overview" not in payload["summary"]),
            not ("observable_mismatch_by_pass" not in payload["summary"]),
            not ("observable_mismatch_map" not in payload["summary"]),
            not ("observable_mismatch_priority" not in payload["summary"]),
            not ("discarded_mutation_summary" not in payload["summary"]),
            not ("discarded_mutation_priority" not in payload["summary"]),
            not ("RegisterSubstitution" not in payload["summary"]["pass_risk_buckets"]["risky"]),
            not ("RegisterSubstitution" not in payload["summary"]["pass_risk_buckets"]["symbolic"]),
            not ("RegisterSubstitution" not in payload["summary"]["report_views"]["passes"]["risky"]),
            payload["summary"]["report_views"]["general_passes"][0][MUTATION_NAME_KEY] == "RegisterSubstitution",
            not ("region_evidence_count" not in payload["summary"]["report_views"]["general_passes"][0]),
            payload["summary"]["report_views"]["general_summary"]["passes"] == ["RegisterSubstitution"],
            payload["summary"]["report_views"]["pass_filter_views"]["only_risky_passes"] == ["RegisterSubstitution"],
            isinstance(payload["summary"]["report_views"]["mismatch_view"], list),
            isinstance(payload["summary"]["report_views"]["only_mismatches"], dict),
            not ("summary" not in payload["summary"]["report_views"]["only_mismatches"]),
            not ("compact_rows" not in payload["summary"]["report_views"]["only_mismatches"]),
        )
        if payload["summary"]["report_views"]["only_mismatches"]["rows"]:
            expect_all(
                not ("role" not in payload["summary"]["report_views"]["only_mismatches"]["rows"][0]),
                not ("symbolic_confidence" not in payload["summary"]["report_views"]["only_mismatches"]["rows"][0]),
            )
        expect_all(
            isinstance(payload["summary"]["report_views"]["discarded_view"], dict),
            isinstance(payload["summary"]["report_views"]["only_failed_gates"], dict),
            not ("severity_priority" not in payload["summary"]["report_views"]["only_failed_gates"]),
            not ("grouped_by_pass" not in payload["summary"]["report_views"]["only_failed_gates"]),
            not ("compact_rows" not in payload["summary"]["report_views"]["only_failed_gates"]),
            not ("expected_severity_counts" not in payload["summary"]["report_views"]["only_failed_gates"]),
            not ("failed" not in payload["summary"]["report_views"]["only_failed_gates"]),
            not ("failure_count" not in payload["summary"]["report_views"]["only_failed_gates"]),
            isinstance(payload["summary"]["report_views"]["validation_adjustments"], dict),
            not ("summary" not in payload["summary"]["report_views"]["validation_adjustments"]),
            not ("by_impact" not in payload["summary"]["report_views"]["discarded_view"]),
            not ("compact_rows" not in payload["summary"]["report_views"]["discarded_view"]),
            isinstance(payload["summary"]["validation_adjustment_rows"], list),
            isinstance(payload["summary"]["report_views"][ONLY_MUTATION_KEY], dict),
            not ("pass_region_evidence_map" not in payload["summary"]),
            not ("RegisterSubstitution" not in payload["summary"]["pass_capabilities"]),
            not ("RegisterSubstitution" not in payload["summary"]["pass_capability_summary_map"]),
            not ("RegisterSubstitution" not in payload["summary"]["pass_triage_map"]),
            payload["summary"]["normalized_pass_results"][0][MUTATION_NAME_KEY] == "RegisterSubstitution",
            payload["summary"]["pass_evidence_map"]["RegisterSubstitution"][MUTATION_NAME_KEY]
            == "RegisterSubstitution",
            payload["summary"]["pass_evidence_priority"][0][MUTATION_NAME_KEY] == "RegisterSubstitution",
            payload["summary"]["symbolic_issue_map"]["RegisterSubstitution"][MUTATION_NAME_KEY]
            == "RegisterSubstitution",
            payload["summary"]["symbolic_coverage_map"]["RegisterSubstitution"][MUTATION_NAME_KEY]
            == "RegisterSubstitution",
            payload["summary"]["symbolic_severity_map"]["RegisterSubstitution"][MUTATION_NAME_KEY]
            == "RegisterSubstitution",
            isinstance(payload["summary"]["observable_mismatch_by_pass"], list),
            isinstance(payload["summary"]["observable_mismatch_map"], dict),
        )

    def test_cli_report_only_covered_passes_filters_real_coverage(self, deterministic_substitute_elf, tmp_path):
        """Filter according to measured coverage, including bounded-only evidence."""
        report = tmp_path / "covered.report.json"
        filtered = tmp_path / "covered.filtered.json"

        with MorphEngine(config={"seed": 1337}) as engine:
            engine.load_binary(deterministic_substitute_elf).analyze()
            engine.add_mutation(
                InstructionSubstitutionPass(
                    config={
                        "probability": 1.0,
                        "max_substitutions_per_function": 8,
                        "strict_size": True,
                        "seed": 1337,
                    }
                )
            )
            engine.run(EngineRunOptions(validation_mode="symbolic", seed=1337, report_path=report))

        expect(report.exists())
        source_payload = json.loads(report.read_text(encoding="utf-8"))
        covered_passes = source_payload["summary"]["pass_coverage_buckets"]["covered"]

        report_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-covered-passes",
                "--summary-only",
                "--require-results",
                "--output",
                str(filtered),
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(report_result.returncode == (0 if covered_passes else 1))
        expect("Covered Pass Filter" in report_result.stdout)

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        expect(
            filtered_payload["report_filters"]["only_covered_passes"] is True
            and filtered_payload["filtered_summary"]["covered_passes"] == covered_passes
            and filtered_payload["filtered_summary"]["pass_coverage_buckets"]["covered"] == covered_passes
            and [row[MUTATION_NAME_KEY] for row in filtered_payload["filtered_summary"]["pass_evidence"]]
            == covered_passes
        )

    def test_cli_report_only_uncovered_passes_filters_real_uncovered_passes(self, ls_elf, tmp_path):
        """Test `report --only-uncovered-passes` on a real clean report without symbolic coverage."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")
        report = tmp_path / "uncovered.report.json"
        filtered = tmp_path / "uncovered.filtered.json"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(_ReportFixturePass())
            engine.run(EngineRunOptions(validation_mode="off", report_path=report))

        expect(report.exists())

        report_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-uncovered-passes",
                "--summary-only",
                "--require-results",
                "--output",
                str(filtered),
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(report_result.returncode == 0)
        expect(not ("Uncovered Pass Filter" not in report_result.stdout))
        expect(not ("ReportFixture" not in report_result.stdout))

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        expect(not (filtered_payload["report_filters"]["only_uncovered_passes"] is not True))
        expect(not ("ReportFixture" not in filtered_payload["filtered_summary"]["uncovered_passes"]))
        expect(not ("ReportFixture" not in filtered_payload["filtered_summary"]["pass_coverage_buckets"]["uncovered"]))
        expect(filtered_payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "ReportFixture")
