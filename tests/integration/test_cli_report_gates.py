"""
Integration tests for CLI.
"""

import importlib
import importlib.util
import json
import sys

import pytest

from tests.integration.cli_test_support import CLIIntegrationBase
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

    def test_cli_report_can_filter_degraded_validation_runs(
        self,
        deterministic_register_elf,
        tmp_path,
    ):
        """Report can triage a real run where validation mode was degraded."""
        output_path = tmp_path / "register_degraded.bin"
        report_path = tmp_path / "register_degraded.report.json"
        filtered_path = tmp_path / "register_degraded.filtered.json"

        mutate_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(deterministic_register_elf),
                "-o",
                str(output_path),
                "--report",
                str(report_path),
                "--validation-mode",
                "symbolic",
                "--limited-symbolic-policy",
                "degrade-runtime",
                "--seed",
                "1337",
                "-m",
                "register",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(mutate_result.returncode == 0)
        expect(report_path.exists())

        report_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-degraded",
                "--summary-only",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(report_result.returncode == 0)
        expect(not ("Validation Mode Adjustment" not in report_result.stdout))
        expect(not ("requested=symbolic, effective=runtime" not in report_result.stdout))
        expect(not ("Degradation Roles" not in report_result.stdout))
        expect(not ("Degraded Severity Priority" not in report_result.stdout))
        expect(not ("degradation-trigger: 1" not in report_result.stdout))
        expect(not ("Pass Validation Context" not in report_result.stdout))
        expect(not ("RegisterSubstitution" not in report_result.stdout))

        export_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-degraded",
                "--output",
                str(filtered_path),
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(export_result.returncode == 0)
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        expect(not (filtered_payload["report_filters"]["only_degraded"] is not True))
        expect(not (filtered_payload["filtered_summary"]["degraded_validation"] is not True))
        expect(filtered_payload["filtered_summary"]["requested_validation_mode"] == "symbolic")
        expect(filtered_payload["filtered_summary"]["validation_mode"] == "runtime")
        expect(filtered_payload["filtered_summary"]["degraded_passes"])
        expect(filtered_payload["filtered_summary"]["degraded_passes"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
        expect(
            filtered_payload["filtered_summary"]["symbolic_severity_by_pass"][0][MUTATION_NAME_KEY]
            == "RegisterSubstitution"
        )
        expect(filtered_payload["filtered_summary"]["degradation_roles"]["degradation-trigger"] == 1)

        mismatch_filtered_path = tmp_path / "mismatch-filtered.json"
        mismatch_export_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-degraded",
                "--only-mismatches",
                "--output",
                str(mismatch_filtered_path),
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(mismatch_export_result.returncode == 0)
        expect(not ("Mismatch Degradation Context" not in mismatch_export_result.stdout))
        expect(not ("Mismatch Severity Priority" not in mismatch_export_result.stdout))
        expect(not ("requested=symbolic, effective=runtime" not in mismatch_export_result.stdout))
        expect(not ("trigger_passes=RegisterSubstitution" not in mismatch_export_result.stdout))
        mismatch_payload = json.loads(mismatch_filtered_path.read_text(encoding="utf-8"))
        expect(not (mismatch_payload["report_filters"]["only_degraded"] is not True))
        expect(not (mismatch_payload["report_filters"]["only_mismatches"] is not True))
        expect(mismatch_payload["filtered_summary"]["requested_validation_mode"] == "symbolic")
        expect(mismatch_payload["filtered_summary"]["validation_mode"] == "runtime")
        expect(not (mismatch_payload["filtered_summary"]["degraded_validation"] is not True))
        expect(mismatch_payload["filtered_summary"]["degraded_passes"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
        expect(mismatch_payload["filtered_summary"]["degradation_roles"]["degradation-trigger"] == 1)
        expect(
            mismatch_payload["filtered_summary"]["symbolic_severity_by_pass"][0][MUTATION_NAME_KEY]
            == "RegisterSubstitution"
        )

    def test_cli_report_can_filter_failed_gates(self, ls_elf, tmp_path):
        """Report can triage a real run where mutate finished with failed CLI gates."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "failed_gate.bin"
        report_path = tmp_path / "failed_gate.report.json"
        filtered_path = tmp_path / "failed_gate.filtered.json"

        mutate_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(ls_elf),
                "-o",
                str(output_path),
                "--report",
                str(report_path),
                "--validation-mode",
                "structural",
                "--min-severity",
                "clean",
                "--seed",
                "1337",
                "-m",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(mutate_result.returncode == 1)
        expect(report_path.exists())

        report_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-failed-gates",
                "--summary-only",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(report_result.returncode == 0)
        expect(not ("Gate Evaluation" not in report_result.stdout))
        expect(not ("Gate Failure Summary" not in report_result.stdout))
        expect(not ("all_passed=no" not in report_result.stdout))
        expect(not ("min_severity=clean, passed=no" not in report_result.stdout))
        expect(not ("min_severity_failed=yes, require_pass_failures=0" not in report_result.stdout))

        export_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-failed-gates",
                "--output",
                str(filtered_path),
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(export_result.returncode == 0)
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        expect(not (filtered_payload["report_filters"]["only_failed_gates"] is not True))
        expect(not (filtered_payload["filtered_summary"]["failed_gates"] is not True))
        expect(filtered_payload["filtered_summary"]["gate_evaluation"]["requested"]["min_severity"] == "clean")
        expect(not (filtered_payload["filtered_summary"]["gate_evaluation"]["results"]["all_passed"] is not False))
        expect(not (filtered_payload["filtered_summary"]["gate_failures"]["min_severity_failed"] is not True))
        expect(filtered_payload["filtered_summary"]["gate_failures"]["require_pass_severity_failure_count"] == 0)

        require_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-failed-gates",
                "--require-results",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(require_result.returncode == 0)
        expect(not ("Gate Evaluation" not in require_result.stdout))

    def test_cli_report_groups_failed_pass_severity_gates(self, ls_elf, tmp_path):
        """Report groups failed per-pass severity rules for a real mutate report."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "failed_pass_gate.bin"
        report_path = tmp_path / "failed_pass_gate.report.json"

        mutate_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(ls_elf),
                "-o",
                str(output_path),
                "--report",
                str(report_path),
                "--validation-mode",
                "structural",
                "--require-pass-severity",
                "nop=clean",
                "--seed",
                "1337",
                "-m",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(mutate_result.returncode == 1)
        expect(report_path.exists())

        report_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-failed-gates",
                "--summary-only",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(report_result.returncode == 0)
        expect(not ("Gate Failure Summary" not in report_result.stdout))
        expect(not ("require_pass_failures=1" not in report_result.stdout))
        expect(not ("expected_severity_priority=clean:1" not in report_result.stdout))
        expect(not ("Gate Failure By Pass" not in report_result.stdout))
        expect(not ("NopInsertion" not in report_result.stdout))
        expect(not ("NopInsertion=not-requested(expected <= clean)" not in report_result.stdout))

        payload = json.loads(report_path.read_text(encoding="utf-8"))
        expect(
            payload["gate_evaluation"]["results"]["require_pass_severity_failures"]
            == ["NopInsertion=not-requested(expected <= clean)"]
        )

    def test_cli_report_only_expected_severity_filters_real_failed_gates(self, ls_elf, tmp_path):
        """Report filters real failed gate views by expected severity."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_expected_severity.bin"
        report_path = tmp_path / "only_expected_severity.report.json"
        filtered_path = tmp_path / "only_expected_severity.filtered.json"

        mutate_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(ls_elf),
                "-o",
                str(output_path),
                "--report",
                str(report_path),
                "--validation-mode",
                "structural",
                "--require-pass-severity",
                "nop=clean",
                "--require-pass-severity",
                "substitute=bounded-only",
                "--seed",
                "1337",
                "-m",
                "nop",
                "-m",
                "substitute",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(mutate_result.returncode == 1)
        expect(report_path.exists())

        report_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-failed-gates",
                "--only-expected-severity",
                "clean",
                "--summary-only",
                "--output",
                str(filtered_path),
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(report_result.returncode == 0)
        expect(not ("expected_severity_counts=clean:1" not in report_result.stdout))
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        expect(filtered_payload["report_filters"]["only_expected_severity"] == "clean")
        expect(
            filtered_payload["filtered_summary"]["gate_failures"]["require_pass_severity_failures_by_expected_severity"]
            == {"clean": 1}
        )
        expect(
            filtered_payload["filtered_summary"]["gate_failure_priority"]
            == [
                {
                    "pass_name": "NopInsertion",
                    "failure_count": 1,
                    "strictest_expected_severity": "clean",
                    "failures": ["NopInsertion=not-requested(expected <= clean)"],
                }
            ]
        )

    def test_cli_report_only_expected_severity_require_results_on_real_failed_gates(self, ls_elf, tmp_path):
        """Require-results should respect filtered expected-severity gate views."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_expected_severity_require_results.bin"
        report_path = tmp_path / "only_expected_severity_require_results.report.json"

        mutate_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(ls_elf),
                "-o",
                str(output_path),
                "--report",
                str(report_path),
                "--validation-mode",
                "structural",
                "--require-pass-severity",
                "nop=clean",
                "--require-pass-severity",
                "substitute=bounded-only",
                "--seed",
                "1337",
                "-m",
                "nop",
                "-m",
                "substitute",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(mutate_result.returncode == 1)
        expect(report_path.exists())

        success_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-failed-gates",
                "--only-expected-severity",
                "clean",
                "--require-results",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        failure_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-failed-gates",
                "--only-expected-severity",
                "mismatch",
                "--require-results",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(success_result.returncode == 0)
        expect(not ("Gate Failure Summary" not in success_result.stdout))
        expect(failure_result.returncode == 1)
