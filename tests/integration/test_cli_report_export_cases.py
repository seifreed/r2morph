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

    def test_cli_mutate_generated_report_supports_report_filters(self, ls_elf, tmp_path):
        """Test `mutate --report` output can be consumed by `report --only-*` end-to-end."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_symbolic.bin"
        report = tmp_path / "cli_symbolic.report.json"

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
        expect(output_path.exists())
        expect(report.exists())

        payload = json.loads(report.read_text(encoding="utf-8"))
        if not payload["mutations"]:
            # The minimal ELF fixture (1 function) legitimately yields no
            # kept mutations for nop/substitute/register; there is then
            # no report-filter input to exercise here.
            pytest.skip("CLI mutate produced no kept mutations on the minimal fixture")
        mutation = next(
            (item for item in payload["mutations"] if item.get("metadata", {}).get("symbolic_status")),
            None,
        )
        if mutation is None:
            pytest.skip("No symbolic mutation metadata produced by CLI mutate run")

        pass_name = mutation[MUTATION_NAME_KEY]
        symbolic_status = mutation["metadata"]["symbolic_status"]

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

        pass_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-pass",
                pass_name,
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        expect(pass_result.returncode == 0)
        expect(not (f'"pass_name": "{pass_name}"' not in pass_result.stdout))
        expect(not (f'"only_pass": "{pass_name}"' not in pass_result.stdout))

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
        expect(not (f'"only_status": "{symbolic_status}"' not in status_result.stdout))

    def test_cli_report_can_export_filtered_json(self, ls_elf, tmp_path):
        """Test `report --output` writes a filtered JSON artifact from a real CLI report."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_export.bin"
        report = tmp_path / "cli_export.report.json"

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
        expect(report.exists())

        payload = json.loads(report.read_text(encoding="utf-8"))
        mutation = next(
            (item for item in payload.get("mutations", []) if item.get("metadata", {}).get("symbolic_status")),
            None,
        )
        if mutation is None:
            pytest.skip("No symbolic mutation metadata produced by CLI mutate run")

        pass_name = mutation[MUTATION_NAME_KEY]
        symbolic_status = mutation["metadata"]["symbolic_status"]
        filtered_output = tmp_path / "filtered.report.json"

        report_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "report",
                "--only-pass",
                pass_name,
                "--only-status",
                symbolic_status,
                "--output",
                str(filtered_output),
                str(report),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        expect(report_result.returncode == 0)
        expect(filtered_output.exists())
        expect(not ("Filtered report written:" not in report_result.stdout))

        filtered_payload = json.loads(filtered_output.read_text(encoding="utf-8"))
        expect(filtered_payload["report_filters"][ONLY_MUTATION_KEY] == pass_name)
        expect(filtered_payload["report_filters"]["only_status"] == symbolic_status)
        expect(filtered_payload["filtered_summary"]["mutations"] == len(filtered_payload["mutations"]))
        expect(filtered_payload["filtered_summary"]["passes"] == [pass_name])
        expect(
            filtered_payload["filtered_summary"]["symbolic_statuses"]
            == {symbolic_status: len(filtered_payload["mutations"])}
        )
        expect(filtered_payload["mutations"])
        expect(all(item[MUTATION_NAME_KEY] == pass_name for item in filtered_payload["mutations"]))
        expect(
            all(
                item.get("metadata", {}).get("symbolic_status") == symbolic_status
                for item in filtered_payload["mutations"]
            )
        )
