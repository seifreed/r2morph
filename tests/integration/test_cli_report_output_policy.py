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

    def test_cli_report_require_results_uses_exit_code_for_ci(self, ls_elf, tmp_path):
        """Test `report --require-results` succeeds or fails based on real filtered output."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_require.bin"
        report = tmp_path / "cli_require.report.json"

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
                "symbolic",
                "--allow-limited-symbolic",
                "--seed",
                "1337",
                "-m",
                "nop",
                "-m",
                "substitute",
                "-m",
                "register",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(mutate_result.returncode == 0)
        payload = json.loads(report.read_text(encoding="utf-8"))
        mutation = next(
            (item for item in payload.get("mutations", []) if item.get("metadata", {}).get("symbolic_status")),
            None,
        )
        if mutation is None:
            pytest.skip("No symbolic mutation metadata produced by CLI mutate run")

        pass_name = mutation[MUTATION_NAME_KEY]

        success_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-pass",
                pass_name,
                "--require-results",
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        expect(success_result.returncode == 0)
        expect(not (f'"only_pass": "{pass_name}"' not in success_result.stdout))

        empty_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-pass",
                "DefinitelyMissingPass",
                "--require-results",
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        expect(empty_result.returncode == 1)
        expect(not ('"mutations": []' not in empty_result.stdout))

    def test_cli_report_require_results_supports_min_severity(self, ls_elf, tmp_path):
        """Test `report --require-results --min-severity` on a real generated report."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_require_severity.bin"
        report = tmp_path / "cli_require_severity.report.json"

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
                "symbolic",
                "--allow-limited-symbolic",
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

        expect(mutate_result.returncode == 0)

        strict_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--require-results",
                "--min-severity",
                "not-requested",
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        failing_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-pass",
                "DefinitelyMissingPass",
                "--require-results",
                "--min-severity",
                "mismatch",
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(strict_result.returncode == 0)
        expect(failing_result.returncode == 1)

    def test_cli_mutate_min_severity_can_pass(self, ls_elf, tmp_path):
        """`mutate --min-severity` should succeed when the final report meets the threshold."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_min_severity_ok.bin"
        report = tmp_path / "cli_mutate_min_severity_ok.report.json"

        result = run_command(
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
                "--min-severity",
                "not-requested",
                "--seed",
                "1337",
                "-m",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(result.returncode == 0)
        expect(output_path.exists())
        expect(report.exists())
        expect(not ("Severity gate passed:" not in result.stdout))

        payload = json.loads(report.read_text(encoding="utf-8"))
        expect(payload["summary"]["validation_mode"] == "structural")
        expect(payload["summary"]["symbolic_severity_by_pass"][0]["severity"] == "not-requested")
        expect(payload["gate_evaluation"]["requested"]["min_severity"] == "not-requested")
        expect(not (payload["gate_evaluation"]["results"]["min_severity_passed"] is not True))
        expect(not (payload["gate_evaluation"]["results"]["all_passed"] is not True))

    def test_cli_mutate_min_severity_can_fail_without_losing_artifacts(self, ls_elf, tmp_path):
        """`mutate --min-severity` should fail with code 1 but keep output/report artifacts."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_min_severity_fail.bin"
        report = tmp_path / "cli_mutate_min_severity_fail.report.json"

        result = run_command(
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

        expect(result.returncode == 1)
        expect(output_path.exists())
        expect(report.exists())
        expect(not ("Severity gate failed:" not in result.stdout))

        payload = json.loads(report.read_text(encoding="utf-8"))
        expect(payload["summary"]["validation_mode"] == "structural")
        expect(payload["summary"]["symbolic_severity_by_pass"][0]["severity"] == "not-requested")
        expect(payload["gate_evaluation"]["requested"]["min_severity"] == "clean")
        expect(not (payload["gate_evaluation"]["results"]["min_severity_passed"] is not False))
        expect(not (payload["gate_evaluation"]["results"]["all_passed"] is not False))
        expect(not (payload["gate_failures"]["min_severity_failed"] is not True))
        expect(not (payload["summary"]["gate_failures"]["min_severity_failed"] is not True))

    def test_cli_mutate_require_pass_severity_can_pass(self, ls_elf, tmp_path):
        """`mutate --require-pass-severity` should succeed when the named pass meets the threshold."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_pass_severity_ok.bin"
        report = tmp_path / "cli_mutate_pass_severity_ok.report.json"

        result = run_command(
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
                "--require-pass-severity",
                "NopInsertion=not-requested",
                "--seed",
                "1337",
                "-m",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(result.returncode == 0)
        expect(output_path.exists())
        expect(report.exists())
        expect(not ("Pass severity gate passed:" not in result.stdout))
        expect(not ("NopInsertion<=not-requested" not in result.stdout))

        payload = json.loads(report.read_text(encoding="utf-8"))
        expect(payload["passes"]["NopInsertion"]["symbolic_summary"]["severity"] == "not-requested")
        expect(
            payload["gate_evaluation"]["requested"]["require_pass_severity"]
            == [{"pass_name": "NopInsertion", "max_severity": "not-requested"}]
        )
        expect(not (payload["gate_evaluation"]["results"]["require_pass_severity_passed"] is not True))
        expect(payload["gate_evaluation"]["results"]["require_pass_severity_failures"] == [])
        expect(not (payload["gate_evaluation"]["results"]["all_passed"] is not True))
