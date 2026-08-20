"""
Integration tests for CLI.
"""

import importlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.core.engine_run import EngineRunOptions
from r2morph.mutations.base import MutationPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.utils.assertions import expect, expect_all
from tests.utils.field_names import MUTATION_NAME_KEY, ONLY_FAILED_MUTATION_KEY, ONLY_MUTATION_KEY
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


class _ReportFixturePass(MutationPass):
    def __init__(self):
        super().__init__("ReportFixture")

    def apply(self, binary):
        functions = binary.get_functions()
        expect(functions)
        func_addr = functions[0].get("offset", functions[0].get("addr", 0))
        instructions = binary.get_function_disasm(func_addr)
        expect(instructions)
        insn = instructions[0]
        addr = insn.get("addr", 0)
        size = insn.get("size", 1)
        original = binary.read_bytes(addr, size)
        expect(binary.write_bytes(addr, original))
        self._record_mutation(
            function_address=func_addr,
            start_address=addr,
            end_address=addr + size - 1,
            original_bytes=original,
            mutated_bytes=original,
            original_disasm=insn.get("disasm", ""),
            mutated_disasm=insn.get("disasm", ""),
            mutation_kind="report_fixture",
            metadata={"integration": True},
        )
        return {"mutations_applied": 1}


@pytest.mark.skipif(not TYPER_AVAILABLE, reason="typer not installed")
class TestCLI:
    """Tests for r2morph CLI."""

    @pytest.fixture(autouse=True)
    def _require_r2pipe(self):
        if importlib.util.find_spec("r2pipe") is None:
            pytest.skip("r2pipe not installed")
        if importlib.util.find_spec("yaml") is None:
            pytest.skip("pyyaml not installed")

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_cli_help(self):
        """Test CLI help command."""
        result = run_command(
            [sys.executable, "-m", "r2morph.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        expect(result.returncode == 0)
        expect("usage:" in result.stdout.lower() or "r2morph" in result.stdout.lower())

    def test_cli_version(self):
        """Test CLI version command."""
        result = run_command(
            [sys.executable, "-m", "r2morph.cli", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        expect(not (result.returncode not in [0, 2]))

    def test_cli_morph_basic(self, ls_elf, tmp_path):
        """Test basic morph command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_morphed"

        result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "-i",
                str(ls_elf),
                "-o",
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        expect(not (result.returncode not in [0, 1]))

    def test_cli_analyze(self, ls_elf):
        """Test analyze command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        result = run_command(
            [sys.executable, "-m", "r2morph.cli", "analyze", str(ls_elf)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(not (result.returncode not in [0, 1]))

    def test_cli_with_config(self, ls_elf, tmp_path):
        """Test CLI with aggressive mode (config-like behavior)."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_config"

        result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "-i",
                str(ls_elf),
                "-o",
                str(output_path),
                "--aggressive",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        expect(not (result.returncode not in [0, 1]))

    def test_cli_multiple_mutations(self, ls_elf, tmp_path):
        """Test CLI with multiple mutations (using simple mode)."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_multi"

        result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "-i",
                str(ls_elf),
                "-o",
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        expect(not (result.returncode not in [0, 1]))

    def test_cli_validate(self, ls_elf, tmp_path):
        """Test validate command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_validate"

        run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "morph",
                str(ls_elf),
                "-o",
                str(output_path),
                "-m",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if output_path.exists():
            validate_result = run_command(
                [
                    sys.executable,
                    "-m",
                    "r2morph.cli",
                    "validate",
                    str(ls_elf),
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            expect(not (validate_result.returncode not in [0, 1]))

    def test_cli_validate_with_compare_files(self, tmp_path):
        """Test validate command with monitored side-effect files."""
        original = tmp_path / "original.sh"
        mutated = tmp_path / "mutated.sh"
        corpus = tmp_path / "corpus.json"

        original.write_text("#!/bin/sh\nprintf 'A' > side_effect.txt\n", encoding="utf-8")
        mutated.write_text("#!/bin/sh\nprintf 'B' > side_effect.txt\n", encoding="utf-8")
        original.chmod(0o755)
        mutated.chmod(0o755)
        corpus.write_text(
            '[{"description":"side-effect","args":[],"stdin":"","expected_exitcode":0,"monitored_files":["side_effect.txt"]}]',
            encoding="utf-8",
        )

        validate_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "validate",
                str(original),
                str(mutated),
                "--corpus",
                str(corpus),
                "--compare-files",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(validate_result.returncode == 1)
        expect(not ('"files": true' not in validate_result.stdout))
        expect(not ('"side_effect.txt"' not in validate_result.stdout))

    def test_cli_diff(self, ls_elf, tmp_path):
        """Test diff command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_diff"

        run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "morph",
                str(ls_elf),
                "-o",
                str(output_path),
                "-m",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if output_path.exists():
            diff_result = run_command(
                [
                    sys.executable,
                    "-m",
                    "r2morph.cli",
                    "diff",
                    str(ls_elf),
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            expect(not (diff_result.returncode not in [0, 1]))

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

    def test_cli_report_only_covered_passes_filters_real_covered_passes(self, deterministic_substitute_elf, tmp_path):
        """Test `report --only-covered-passes` on a real report with symbolic coverage."""
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

        expect(report_result.returncode == 0)
        expect(not ("Covered Pass Filter" not in report_result.stdout))
        expect(not ("InstructionSubstitution" not in report_result.stdout))

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        expect(not (filtered_payload["report_filters"]["only_covered_passes"] is not True))
        expect(not ("InstructionSubstitution" not in filtered_payload["filtered_summary"]["covered_passes"]))
        expect(
            not (
                "InstructionSubstitution"
                not in filtered_payload["filtered_summary"]["pass_coverage_buckets"]["covered"]
            )
        )
        expect(filtered_payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")

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
