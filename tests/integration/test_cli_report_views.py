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
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.integration.cli_test_support import CLIIntegrationBase, _ReportFixturePass
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY
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

    def test_cli_report_filters_on_engine_generated_report(self, ls_elf, tmp_path):
        """Test report filters against a real engine-generated symbolic report."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        report = tmp_path / "generated.report.json"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(_ReportFixturePass())
            result = engine.run(EngineRunOptions(validation_mode="symbolic", report_path=report))

        expect(report.exists())
        payload = json.loads(report.read_text(encoding="utf-8"))
        expect(payload["mutations"])
        mutation = payload["mutations"][0]
        symbolic_status = mutation["metadata"].get("symbolic_status")
        expect(symbolic_status)
        expect(not ("symbolic_issue_passes" not in payload["summary"]))
        expect(not ("symbolic_coverage_by_pass" not in payload["summary"]))
        expect(not ("symbolic_severity_by_pass" not in payload["summary"]))
        expect(not ("symbolic_summary" not in payload["passes"]["ReportFixture"]))
        expect(not ("severity" not in payload["passes"]["ReportFixture"]["symbolic_summary"]))
        has_symbolic_issue = not mutation["metadata"].get("symbolic_observable_equivalent", False) and (
            mutation["metadata"].get("symbolic_observable_check_performed", False)
            or symbolic_status
            not in {
                "real-binary-observables-match",
                "shellcode-observables-match",
            }
        )
        if has_symbolic_issue:
            expect(payload["summary"]["symbolic_issue_passes"])
            expect(payload["passes"]["ReportFixture"]["symbolic_summary"]["issues"])
        expect(payload["summary"]["symbolic_coverage_by_pass"])
        expect(not (payload["passes"]["ReportFixture"]["symbolic_summary"]["symbolic_requested"] < 1))
        expect(not (result["validation"]["symbolic"]["requested"] is not True))

        summary_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--summary-only",
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        expect(summary_result.returncode == 0)
        expect(not ("Symbolic Mutation Summary" not in summary_result.stdout))
        expect(not ("Severity Priority" not in summary_result.stdout))
        expect(not ("Pass Evidence" not in summary_result.stdout))
        if "RegisterSubstitution" in summary_result.stdout and "NopInsertion" in summary_result.stdout:
            expect(
                not (summary_result.stdout.index("RegisterSubstitution") >= summary_result.stdout.index("NopInsertion"))
            )
        expect(not (has_symbolic_issue and "Passes With Symbolic Issues" not in summary_result.stdout))
        expect('"mutations"' not in summary_result.stdout)

        pass_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-pass",
                "ReportFixture",
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        expect(pass_result.returncode == 0)
        expect(not ("Pass Symbolic Summary" not in pass_result.stdout))
        expect(not ("Pass Evidence Summary" not in pass_result.stdout))
        expect(not ("severity=" not in pass_result.stdout))
        expect(not ('"pass_name": "ReportFixture"' not in pass_result.stdout))
        expect(not ('"report_filters": {' not in pass_result.stdout))
        expect(not ('"only_pass": "ReportFixture"' not in pass_result.stdout))

        status_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-status",
                symbolic_status,
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        expect(status_result.returncode == 0)
        expect(not (f'"symbolic_status": "{symbolic_status}"' not in status_result.stdout))
        expect(not ('"report_filters": {' not in status_result.stdout))
        expect(not (f'"only_status": "{symbolic_status}"' not in status_result.stdout))

    def test_cli_report_only_risky_passes_filters_real_risky_passes(self, deterministic_register_elf, tmp_path):
        """Test `report --only-risky-passes` on a real report with symbolic mismatch evidence."""
        report = tmp_path / "register_risky.report.json"
        filtered = tmp_path / "register_risky.filtered.json"
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

        expect(report.exists())

        report_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-risky-passes",
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
        expect(not ("Risky Pass Filter" not in report_result.stdout))
        expect(not ("RegisterSubstitution" not in report_result.stdout))

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        expect(not (filtered_payload["report_filters"]["only_risky_passes"] is not True))
        expect(not ("RegisterSubstitution" not in filtered_payload["filtered_summary"]["risky_passes"]))
        expect(not ("RegisterSubstitution" not in filtered_payload["filtered_summary"]["pass_risk_buckets"]["risky"]))
        expect(
            not ("RegisterSubstitution" not in filtered_payload["filtered_summary"]["pass_risk_buckets"]["symbolic"])
        )
        expect(filtered_payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")

    def test_cli_report_only_symbolic_risk_filters_real_symbolic_risk(self, deterministic_register_elf, tmp_path):
        """Test `report --only-symbolic-risk` on a real report with symbolic mismatch evidence."""
        report = tmp_path / "register_symbolic_risk.report.json"
        filtered = tmp_path / "register_symbolic_risk.filtered.json"

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

        expect(report.exists())

        report_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-symbolic-risk",
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
        expect(not ("Symbolic Risk Filter" not in report_result.stdout))
        expect(not ("RegisterSubstitution" not in report_result.stdout))

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        expect(not (filtered_payload["report_filters"]["only_symbolic_risk"] is not True))
        expect(not ("RegisterSubstitution" not in filtered_payload["filtered_summary"]["symbolic_risk_passes"]))
        expect(filtered_payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")

    def test_cli_report_only_clean_passes_filters_real_clean_passes(self, ls_elf, tmp_path):
        """Test `report --only-clean-passes` on a real report with clean symbolic evidence."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")
        report = tmp_path / "clean.report.json"
        filtered = tmp_path / "clean.filtered.json"

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
                "--only-clean-passes",
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
        expect(not ("Clean Pass Filter" not in report_result.stdout))
        expect(not ("ReportFixture" not in report_result.stdout))

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        expect(not (filtered_payload["report_filters"]["only_clean_passes"] is not True))
        expect(not ("ReportFixture" not in filtered_payload["filtered_summary"]["clean_passes"]))
        expect(not ("ReportFixture" not in filtered_payload["filtered_summary"]["pass_risk_buckets"]["clean"]))
        expect(filtered_payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "ReportFixture")
