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

    def test_cli_mutate_require_pass_severity_can_fail_without_losing_artifacts(self, ls_elf, tmp_path):
        """`mutate --require-pass-severity` should fail with code 1 but keep artifacts."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_pass_severity_fail.bin"
        report = tmp_path / "cli_mutate_pass_severity_fail.report.json"

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
                "NopInsertion=clean",
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
        expect(not ("Pass severity gate failed:" not in result.stdout))
        expect(not ("NopInsertion=not-requested(expected <= clean)" not in result.stdout))

        payload = json.loads(report.read_text(encoding="utf-8"))
        expect(payload["passes"]["NopInsertion"]["symbolic_summary"]["severity"] == "not-requested")
        expect(
            payload["gate_evaluation"]["requested"]["require_pass_severity"]
            == [{"pass_name": "NopInsertion", "max_severity": "clean"}]
        )
        expect(not (payload["gate_evaluation"]["results"]["require_pass_severity_passed"] is not False))
        expect(
            payload["gate_evaluation"]["results"]["require_pass_severity_failures"]
            == ["NopInsertion=not-requested(expected <= clean)"]
        )
        expect(not (payload["gate_evaluation"]["results"]["all_passed"] is not False))
        expect(payload["gate_failures"]["require_pass_severity_failure_count"] == 1)
        expect(
            payload["gate_failure_priority"]
            == [
                {
                    "pass_name": "NopInsertion",
                    "failure_count": 1,
                    "strictest_expected_severity": "clean",
                    "failures": ["NopInsertion=not-requested(expected <= clean)"],
                }
            ]
        )
        expect(payload["gate_failure_severity_priority"] == [{"severity": "clean", "failure_count": 1}])
        expect(payload["gate_failures"]["require_pass_severity_failures_by_expected_severity"] == {"clean": 1})
        expect(payload["summary"]["gate_failures"]["require_pass_severity_failure_count"] == 1)
        expect(payload["summary"]["gate_failure_priority"] == payload["gate_failure_priority"])
        expect(payload["summary"]["gate_failure_severity_priority"] == payload["gate_failure_severity_priority"])

    def test_cli_mutate_require_pass_severity_accepts_mutation_alias(self, ls_elf, tmp_path):
        """Short mutation aliases should resolve to the concrete pass name."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_pass_alias_ok.bin"
        report = tmp_path / "cli_mutate_pass_alias_ok.report.json"

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
                "nop=not-requested",
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

    def test_cli_mutate_require_pass_severity_alias_can_fail(self, ls_elf, tmp_path):
        """Short mutation aliases should produce the same failure semantics as pass names."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_pass_alias_fail.bin"
        report = tmp_path / "cli_mutate_pass_alias_fail.report.json"

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

        expect(result.returncode == 1)
        expect(output_path.exists())
        expect(report.exists())
        expect(not ("Pass severity gate failed:" not in result.stdout))
        expect(not ("NopInsertion=not-requested(expected <= clean)" not in result.stdout))

    def test_cli_mutate_require_pass_severity_rejects_unknown_alias(self, ls_elf, tmp_path):
        """Unknown aliases should fail fast with exit code 2 before mutating."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_pass_alias_invalid.bin"
        report = tmp_path / "cli_mutate_pass_alias_invalid.report.json"

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
                "definitely-missing=clean",
                "--seed",
                "1337",
                "-m",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(result.returncode == _EXPECTED_RESULT_RETURNCODE_2)
        expect(not (output_path.exists()))
        expect(not (report.exists()))
        expect(not ("Invalid --require-pass-severity: definitely-missing=clean" not in result.stdout))

    def test_cli_symbolic_blocks_limited_pass_without_override(
        self,
        deterministic_register_elf,
        tmp_path,
    ):
        """Symbolic mode should fail fast for passes that declare limited symbolic support."""
        output_path = tmp_path / "register_blocked.bin"

        result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(deterministic_register_elf),
                "-o",
                str(output_path),
                "--validation-mode",
                "symbolic",
                "--seed",
                "1337",
                "-m",
                "register",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(result.returncode == _EXPECTED_RESULT_RETURNCODE_2_2)
        expect(not ("symbolic validation is marked limited" not in result.stdout))
        expect(not ("--allow-limited-symbolic" not in result.stdout))
        expect(not (output_path.exists()))

    def test_cli_symbolic_allows_limited_pass_with_override(
        self,
        deterministic_register_elf,
        tmp_path,
    ):
        """The explicit override should allow the limited symbolic pass to run."""
        output_path = tmp_path / "register_allowed.bin"
        report_path = tmp_path / "register_allowed.report.json"

        result = run_command(
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
                "--allow-limited-symbolic",
                "--seed",
                "1337",
                "-m",
                "register",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(result.returncode == 0)
        expect(not ("Limited symbolic coverage explicitly allowed" not in result.stdout))
        expect(output_path.exists())
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        expect(
            not (
                payload["pass_support"]["RegisterSubstitution"]["validator_capabilities"]["symbolic"]["recommended"]
                is not False
            )
        )

    def test_cli_symbolic_can_degrade_limited_pass_to_runtime(
        self,
        deterministic_register_elf,
        tmp_path,
    ):
        """Limited symbolic support can degrade to runtime validation instead of blocking."""
        output_path = tmp_path / "register_runtime.bin"
        report_path = tmp_path / "register_runtime.report.json"

        result = run_command(
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

        expect(result.returncode == 0)
        expect(not ("Degrading validation mode from symbolic to runtime" not in result.stdout))
        expect(output_path.exists())
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        expect(payload["summary"]["requested_validation_mode"] == "symbolic")
        expect(payload["summary"]["validation_mode"] == "runtime")
        expect(payload["summary"]["degradation_roles"]["degradation-trigger"] == 1)
        expect(payload["validation_policy"]["policy"] == "degrade-runtime")
        expect(payload["validation_policy"]["reason"] == "limited-symbolic-support")
        expect(payload["validation_policy"]["limited_passes"][0]["role"] == "degradation-trigger")
        expect(not (payload["validation"]["runtime"]["passed"] not in {True, False}))
        expect(
            payload["passes"]["RegisterSubstitution"]["validation_context"]["requested_validation_mode"] == "symbolic"
        )
        expect(
            payload["passes"]["RegisterSubstitution"]["validation_context"]["effective_validation_mode"] == "runtime"
        )
        expect(not (payload["passes"]["RegisterSubstitution"]["validation_context"]["degraded_execution"] is not True))
        expect(
            not (
                payload["passes"]["RegisterSubstitution"]["validation_context"]["degradation_triggered_by_pass"]
                is not True
            )
        )
        expect(payload["passes"]["RegisterSubstitution"]["validation_context"]["role"] == "degradation-trigger")

    def test_cli_symbolic_can_degrade_limited_pass_to_structural(
        self,
        deterministic_register_elf,
        tmp_path,
    ):
        """Limited symbolic support can degrade to structural validation instead of blocking."""
        output_path = tmp_path / "register_structural.bin"
        report_path = tmp_path / "register_structural.report.json"

        result = run_command(
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
                "degrade-structural",
                "--seed",
                "1337",
                "-m",
                "register",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        expect(result.returncode == 0)
        expect(not ("Degrading validation mode from symbolic to structural" not in result.stdout))
        expect(output_path.exists())
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        expect(payload["summary"]["requested_validation_mode"] == "symbolic")
        expect(payload["summary"]["validation_mode"] == "structural")
        expect(payload["summary"]["degradation_roles"]["degradation-trigger"] == 1)
        expect(payload["validation_policy"]["policy"] == "degrade-structural")
        expect(payload["validation_policy"]["reason"] == "limited-symbolic-support")
        expect(payload["validation_policy"]["limited_passes"][0]["role"] == "degradation-trigger")
        expect("runtime" not in payload["validation"])
        expect(payload["passes"]["RegisterSubstitution"]["validation_context"]["role"] == "degradation-trigger")
