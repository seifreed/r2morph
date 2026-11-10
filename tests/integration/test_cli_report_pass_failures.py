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
from tests.utils.field_names import ONLY_FAILED_MUTATION_KEY
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

    def test_cli_report_only_pass_failure_filters_real_failed_gates(self, ls_elf, tmp_path):
        """Report filters real failed gates to a single pass failure."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_pass_failure.bin"
        report_path = tmp_path / "only_pass_failure.report.json"
        filtered_path = tmp_path / "only_pass_failure.filtered.json"

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
                "--only-pass-failure",
                "NopInsertion",
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
        expect(filtered_payload["report_filters"][ONLY_FAILED_MUTATION_KEY] == "NopInsertion")
        expect(
            filtered_payload["filtered_summary"]["gate_failures"]["require_pass_severity_failures_by_pass"]
            == {"NopInsertion": ["NopInsertion=not-requested(expected <= clean)"]}
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

    def test_cli_report_only_pass_failure_require_results_on_real_failed_gates(self, ls_elf, tmp_path):
        """Require-results should respect filtered pass-specific gate views."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_pass_failure_require_results.bin"
        report_path = tmp_path / "only_pass_failure_require_results.report.json"

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
                "--only-pass-failure",
                "NopInsertion",
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
                "--only-pass-failure",
                "RegisterSubstitution",
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

    def test_cli_report_only_pass_failure_accepts_mutation_alias(self, ls_elf, tmp_path):
        """Report accepts stable mutation aliases for pass-failure filtering."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_pass_failure_alias.bin"
        report_path = tmp_path / "only_pass_failure_alias.report.json"
        filtered_path = tmp_path / "only_pass_failure_alias.filtered.json"

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
                "--only-pass-failure",
                "nop",
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
        expect(not ("Pass Failure Filter Resolution" not in report_result.stdout))
        expect(not ("nop -> NopInsertion" not in report_result.stdout))
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        expect(filtered_payload["report_filters"][ONLY_FAILED_MUTATION_KEY] == "NopInsertion")
        expect(filtered_payload["filtered_summary"][ONLY_FAILED_MUTATION_KEY] == "NopInsertion")

    def test_cli_report_only_pass_accepts_mutation_alias(self, ls_elf, tmp_path):
        """Report accepts stable mutation aliases for pass filtering."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_pass_alias.bin"
        report = tmp_path / "only_pass_alias.report.json"
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
                str(report),
                "--validation-mode",
                "structural",
                "--seed",
                "1337",
                "-m",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        expect(mutate_result.returncode == 0)
        expect(report.exists())

        pass_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-pass",
                "nop",
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(pass_result.returncode == 0)
        expect(not ("Pass Filter Resolution" not in pass_result.stdout))
        expect(not ("nop -> NopInsertion" not in pass_result.stdout))
        expect(not ('"report_filters": {' not in pass_result.stdout))
        expect(not ('"only_pass": "NopInsertion"' not in pass_result.stdout))
        expect(not ('"pass_name": "NopInsertion"' not in pass_result.stdout))
