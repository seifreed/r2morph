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

    def test_cli_report_orders_failed_pass_severity_gates_by_expected_severity(self, ls_elf, tmp_path):
        """Report orders grouped pass failures by stricter expected severity first."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "failed_pass_gate_order.bin"
        report_path = tmp_path / "failed_pass_gate_order.report.json"

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
                "--summary-only",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(report_result.returncode == 0)
        expect(not ("expected_severity_counts=bounded-only:1, clean:1" not in report_result.stdout))
        section = report_result.stdout.split("Gate Failure By Pass", 1)[1]
        expect(not ("count=1, strictest_expected=bounded-only" not in section))
        expect(not ("count=1, strictest_expected=clean" not in section))
        expect(not (section.index("InstructionSubstitution") >= section.index("NopInsertion")))

        payload = json.loads(report_path.read_text(encoding="utf-8"))
        failures = payload["gate_evaluation"]["results"]["require_pass_severity_failures"]
        expect(not ("InstructionSubstitution=not-requested(expected <= bounded-only)" not in failures))
        expect(not ("NopInsertion=not-requested(expected <= clean)" not in failures))

    def test_cli_report_breaks_same_severity_gate_ties_by_failure_count(self, ls_elf, tmp_path):
        """Report orders same-severity gate failures by number of failures for the pass."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "failed_pass_gate_count_order.bin"
        report_path = tmp_path / "failed_pass_gate_count_order.report.json"

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
                "nop=clean",
                "--require-pass-severity",
                "substitute=clean",
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
                "--summary-only",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(report_result.returncode == 0)
        expect(not ("expected_severity_counts=clean:3" not in report_result.stdout))
        section = report_result.stdout.split("Gate Failure By Pass", 1)[1]
        expect(not ("count=2, strictest_expected=clean" not in section))
        expect(not (section.index("NopInsertion") >= section.index("InstructionSubstitution")))

        payload = json.loads(report_path.read_text(encoding="utf-8"))
        failures = payload["gate_evaluation"]["results"]["require_pass_severity_failures"]
        expect(
            failures.count("NopInsertion=not-requested(expected <= clean)")
            == _EXPECTED_FAILURES_COUNT_NOPINSERTION_NOT_REQUESTED_EXP_2
        )
        expect(not ("InstructionSubstitution=not-requested(expected <= clean)" not in failures))

    def test_cli_report_exports_gate_failure_priority_for_real_failed_gates(self, ls_elf, tmp_path):
        """Filtered report JSON preserves ordered gate failure priority for real runs."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "failed_pass_gate_priority.bin"
        report_path = tmp_path / "failed_pass_gate_priority.report.json"
        filtered_path = tmp_path / "failed_pass_gate_priority.filtered.json"

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
                "nop=clean",
                "--require-pass-severity",
                "substitute=clean",
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
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        priority = filtered_payload["filtered_summary"]["gate_failure_priority"]
        severity_counts = filtered_payload["filtered_summary"]["gate_failures"][
            "require_pass_severity_failures_by_expected_severity"
        ]
        expect([row[MUTATION_NAME_KEY] for row in priority] == ["NopInsertion", "InstructionSubstitution"])
        expect(priority[0]["failure_count"] == _EXPECTED_PRIORITY_0_FAILURE_COUNT_2)
        expect(priority[0]["strictest_expected_severity"] == "clean")
        expect(severity_counts == {"clean": 3})
