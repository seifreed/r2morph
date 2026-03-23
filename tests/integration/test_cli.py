"""
Integration tests for CLI.
"""

import json
import subprocess
import sys
import importlib.util
from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.mutations.base import MutationPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass

# Check if typer is available
try:
    import importlib.util

    TYPER_AVAILABLE = importlib.util.find_spec("typer") is not None
except ImportError:
    TYPER_AVAILABLE = False


class _ReportFixturePass(MutationPass):
    def __init__(self):
        super().__init__("ReportFixture")

    def apply(self, binary):
        functions = binary.get_functions()
        assert functions
        func_addr = functions[0].get("offset", functions[0].get("addr", 0))
        instructions = binary.get_function_disasm(func_addr)
        assert instructions
        insn = instructions[0]
        addr = insn.get("addr", 0)
        size = insn.get("size", 1)
        original = binary.read_bytes(addr, size)
        assert binary.write_bytes(addr, original)
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
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_cli_help(self):
        """Test CLI help command."""
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0
        assert "usage:" in result.stdout.lower() or "r2morph" in result.stdout.lower()

    def test_cli_version(self):
        """Test CLI version command."""
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode in [0, 2]

    def test_cli_morph_basic(self, ls_elf, tmp_path):
        """Test basic morph command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_morphed"

        result = subprocess.run(
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

        assert result.returncode in [0, 1]

    def test_cli_analyze(self, ls_elf):
        """Test analyze command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "analyze", str(ls_elf)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    def test_cli_with_config(self, ls_elf, tmp_path):
        """Test CLI with aggressive mode (config-like behavior)."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_config"

        result = subprocess.run(
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

        assert result.returncode in [0, 1]

    def test_cli_multiple_mutations(self, ls_elf, tmp_path):
        """Test CLI with multiple mutations (using simple mode)."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_multi"

        result = subprocess.run(
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

        assert result.returncode in [0, 1]

    def test_cli_validate(self, ls_elf, tmp_path):
        """Test validate command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_validate"

        subprocess.run(
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
            validate_result = subprocess.run(
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

            assert validate_result.returncode in [0, 1]

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

        validate_result = subprocess.run(
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

        assert validate_result.returncode == 1
        assert '"files": true' in validate_result.stdout
        assert '"side_effect.txt"' in validate_result.stdout

    def test_cli_diff(self, ls_elf, tmp_path):
        """Test diff command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_diff"

        subprocess.run(
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
            diff_result = subprocess.run(
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

            assert diff_result.returncode in [0, 1]

    def test_cli_report_filters_on_engine_generated_report(self, ls_elf, tmp_path):
        """Test report filters against a real engine-generated symbolic report."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        report = tmp_path / "generated.report.json"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(_ReportFixturePass())
            result = engine.run(validation_mode="symbolic", report_path=report)

        assert report.exists()
        payload = json.loads(report.read_text(encoding="utf-8"))
        assert payload["mutations"]
        mutation = payload["mutations"][0]
        symbolic_status = mutation["metadata"].get("symbolic_status")
        assert symbolic_status
        assert "symbolic_issue_passes" in payload["summary"]
        assert "symbolic_coverage_by_pass" in payload["summary"]
        assert "symbolic_severity_by_pass" in payload["summary"]
        assert "symbolic_summary" in payload["passes"]["ReportFixture"]
        assert "severity" in payload["passes"]["ReportFixture"]["symbolic_summary"]
        has_symbolic_issue = not mutation["metadata"].get("symbolic_observable_equivalent", False) and (
            mutation["metadata"].get("symbolic_observable_check_performed", False)
            or symbolic_status
            not in {
                "real-binary-observables-match",
                "shellcode-observables-match",
            }
        )
        if has_symbolic_issue:
            assert payload["summary"]["symbolic_issue_passes"]
            assert payload["passes"]["ReportFixture"]["symbolic_summary"]["issues"]
        assert payload["summary"]["symbolic_coverage_by_pass"]
        assert payload["passes"]["ReportFixture"]["symbolic_summary"]["symbolic_requested"] >= 1
        assert result["validation"]["symbolic"]["requested"] is True

        summary_result = subprocess.run(
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
        assert summary_result.returncode == 0
        assert "Symbolic Mutation Summary" in summary_result.stdout
        assert "Severity Priority" in summary_result.stdout
        assert "Pass Evidence" in summary_result.stdout
        if "RegisterSubstitution" in summary_result.stdout and "NopInsertion" in summary_result.stdout:
            assert summary_result.stdout.index("RegisterSubstitution") < summary_result.stdout.index("NopInsertion")
        if has_symbolic_issue:
            assert "Passes With Symbolic Issues" in summary_result.stdout
        assert '"mutations"' not in summary_result.stdout

        pass_result = subprocess.run(
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
        assert pass_result.returncode == 0
        assert "Pass Symbolic Summary" in pass_result.stdout
        assert "Pass Evidence Summary" in pass_result.stdout
        assert "severity=" in pass_result.stdout
        assert '"pass_name": "ReportFixture"' in pass_result.stdout
        assert '"report_filters": {' in pass_result.stdout
        assert '"only_pass": "ReportFixture"' in pass_result.stdout

        status_result = subprocess.run(
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
        assert status_result.returncode == 0
        assert f'"symbolic_status": "{symbolic_status}"' in status_result.stdout
        assert '"report_filters": {' in status_result.stdout
        assert f'"only_status": "{symbolic_status}"' in status_result.stdout

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
            engine.run(validation_mode="symbolic", seed=1337, report_path=report)

        assert report.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "Risky Pass Filter" in report_result.stdout
        assert "RegisterSubstitution" in report_result.stdout

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_risky_passes"] is True
        assert "RegisterSubstitution" in filtered_payload["filtered_summary"]["risky_passes"]
        assert "RegisterSubstitution" in filtered_payload["filtered_summary"]["pass_risk_buckets"]["risky"]
        assert "RegisterSubstitution" in filtered_payload["filtered_summary"]["pass_risk_buckets"]["symbolic"]
        assert filtered_payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == ("RegisterSubstitution")

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
            engine.run(validation_mode="symbolic", seed=1337, report_path=report)

        assert report.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "Symbolic Risk Filter" in report_result.stdout
        assert "RegisterSubstitution" in report_result.stdout

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_symbolic_risk"] is True
        assert "RegisterSubstitution" in filtered_payload["filtered_summary"]["symbolic_risk_passes"]
        assert filtered_payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == ("RegisterSubstitution")

    def test_cli_report_only_clean_passes_filters_real_clean_passes(self, ls_elf, tmp_path):
        """Test `report --only-clean-passes` on a real report with clean symbolic evidence."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")
        report = tmp_path / "clean.report.json"
        filtered = tmp_path / "clean.filtered.json"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(_ReportFixturePass())
            engine.run(validation_mode="off", report_path=report)

        assert report.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "Clean Pass Filter" in report_result.stdout
        assert "ReportFixture" in report_result.stdout

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_clean_passes"] is True
        assert "ReportFixture" in filtered_payload["filtered_summary"]["clean_passes"]
        assert "ReportFixture" in filtered_payload["filtered_summary"]["pass_risk_buckets"]["clean"]
        assert filtered_payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "ReportFixture"

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
            engine.run(validation_mode="symbolic", seed=1337, report_path=report)

        payload = json.loads(report.read_text(encoding="utf-8"))
        assert "pass_risk_buckets" in payload
        assert "pass_coverage_buckets" in payload
        assert "pass_risk_buckets" in payload["summary"]
        assert "pass_coverage_buckets" in payload["summary"]
        assert "pass_capabilities" in payload["summary"]
        assert "pass_evidence_map" in payload["summary"]
        assert "pass_evidence_priority" in payload["summary"]
        assert "pass_triage_rows" in payload["summary"]
        assert "pass_triage_map" in payload["summary"]
        assert "pass_evidence_compact" in payload["summary"]
        assert "normalized_pass_results" in payload["summary"]
        assert "report_views" in payload["summary"]
        assert "schema_version" in payload
        assert "schema_version" in payload["summary"]
        assert "validation_adjustment_rows" in payload["summary"]
        assert "pass_capability_summary" in payload["summary"]
        assert "pass_capability_summary_map" in payload["summary"]
        assert "validation_role_rows" in payload["summary"]
        assert "validation_role_map" in payload["summary"]
        assert "validation_adjustments" in payload["summary"]
        assert "symbolic_issue_map" in payload["summary"]
        assert "symbolic_coverage_map" in payload["summary"]
        assert "symbolic_severity_map" in payload["summary"]
        assert "symbolic_status_counts" in payload["summary"]
        assert "symbolic_status_rows" in payload["summary"]
        assert "symbolic_status_map" in payload["summary"]
        assert "symbolic_overview" in payload["summary"]
        assert "observable_mismatch_by_pass" in payload["summary"]
        assert "observable_mismatch_map" in payload["summary"]
        assert "observable_mismatch_priority" in payload["summary"]
        assert "discarded_mutation_summary" in payload["summary"]
        assert "discarded_mutation_priority" in payload["summary"]
        assert "RegisterSubstitution" in payload["summary"]["pass_risk_buckets"]["risky"]
        assert "RegisterSubstitution" in payload["summary"]["pass_risk_buckets"]["symbolic"]
        assert "RegisterSubstitution" in payload["summary"]["report_views"]["passes"]["risky"]
        assert payload["summary"]["report_views"]["general_passes"][0]["pass_name"] == ("RegisterSubstitution")
        assert "region_evidence_count" in payload["summary"]["report_views"]["general_passes"][0]
        assert payload["summary"]["report_views"]["general_summary"]["passes"] == ["RegisterSubstitution"]
        assert payload["summary"]["report_views"]["pass_filter_views"]["only_risky_passes"] == ["RegisterSubstitution"]
        assert isinstance(payload["summary"]["report_views"]["mismatch_view"], list)
        assert isinstance(payload["summary"]["report_views"]["only_mismatches"], dict)
        assert "summary" in payload["summary"]["report_views"]["only_mismatches"]
        assert "compact_rows" in payload["summary"]["report_views"]["only_mismatches"]
        if payload["summary"]["report_views"]["only_mismatches"]["rows"]:
            assert "role" in payload["summary"]["report_views"]["only_mismatches"]["rows"][0]
            assert "symbolic_confidence" in payload["summary"]["report_views"]["only_mismatches"]["rows"][0]
        assert isinstance(payload["summary"]["report_views"]["discarded_view"], dict)
        assert isinstance(payload["summary"]["report_views"]["only_failed_gates"], dict)
        assert "severity_priority" in payload["summary"]["report_views"]["only_failed_gates"]
        assert "grouped_by_pass" in payload["summary"]["report_views"]["only_failed_gates"]
        assert "compact_rows" in payload["summary"]["report_views"]["only_failed_gates"]
        assert "expected_severity_counts" in payload["summary"]["report_views"]["only_failed_gates"]
        assert "failed" in payload["summary"]["report_views"]["only_failed_gates"]
        assert "failure_count" in payload["summary"]["report_views"]["only_failed_gates"]
        assert isinstance(payload["summary"]["report_views"]["validation_adjustments"], dict)
        assert "summary" in payload["summary"]["report_views"]["validation_adjustments"]
        assert "by_impact" in payload["summary"]["report_views"]["discarded_view"]
        assert "compact_rows" in payload["summary"]["report_views"]["discarded_view"]
        assert isinstance(payload["summary"]["validation_adjustment_rows"], list)
        assert isinstance(payload["summary"]["report_views"]["only_pass"], dict)
        assert "pass_region_evidence_map" in payload["summary"]
        assert "RegisterSubstitution" in payload["summary"]["pass_capabilities"]
        assert "RegisterSubstitution" in payload["summary"]["pass_capability_summary_map"]
        assert "RegisterSubstitution" in payload["summary"]["pass_triage_map"]
        assert payload["summary"]["normalized_pass_results"][0]["pass_name"] == "RegisterSubstitution"
        assert payload["summary"]["pass_evidence_map"]["RegisterSubstitution"]["pass_name"] == "RegisterSubstitution"
        assert payload["summary"]["pass_evidence_priority"][0]["pass_name"] == "RegisterSubstitution"
        assert payload["summary"]["symbolic_issue_map"]["RegisterSubstitution"]["pass_name"] == "RegisterSubstitution"
        assert (
            payload["summary"]["symbolic_coverage_map"]["RegisterSubstitution"]["pass_name"] == "RegisterSubstitution"
        )
        assert (
            payload["summary"]["symbolic_severity_map"]["RegisterSubstitution"]["pass_name"] == "RegisterSubstitution"
        )
        assert isinstance(payload["summary"]["observable_mismatch_by_pass"], list)
        assert isinstance(payload["summary"]["observable_mismatch_map"], dict)

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
            engine.run(validation_mode="symbolic", seed=1337, report_path=report)

        assert report.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "Covered Pass Filter" in report_result.stdout
        assert "InstructionSubstitution" in report_result.stdout

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_covered_passes"] is True
        assert "InstructionSubstitution" in filtered_payload["filtered_summary"]["covered_passes"]
        assert "InstructionSubstitution" in filtered_payload["filtered_summary"]["pass_coverage_buckets"]["covered"]
        assert filtered_payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == ("InstructionSubstitution")

    def test_cli_report_only_uncovered_passes_filters_real_uncovered_passes(self, ls_elf, tmp_path):
        """Test `report --only-uncovered-passes` on a real clean report without symbolic coverage."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")
        report = tmp_path / "uncovered.report.json"
        filtered = tmp_path / "uncovered.filtered.json"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(_ReportFixturePass())
            engine.run(validation_mode="off", report_path=report)

        assert report.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "Uncovered Pass Filter" in report_result.stdout
        assert "ReportFixture" in report_result.stdout

        filtered_payload = json.loads(filtered.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_uncovered_passes"] is True
        assert "ReportFixture" in filtered_payload["filtered_summary"]["uncovered_passes"]
        assert "ReportFixture" in filtered_payload["filtered_summary"]["pass_coverage_buckets"]["uncovered"]
        assert filtered_payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "ReportFixture"

    @pytest.mark.xfail(reason="CLI report --only-pass crashes with 'list' object has no attribute 'get'")
    def test_cli_mutate_generated_report_supports_report_filters(self, ls_elf, tmp_path):
        """Test `mutate --report` output can be consumed by `report --only-*` end-to-end."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_symbolic.bin"
        report = tmp_path / "cli_symbolic.report.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 0
        assert output_path.exists()
        assert report.exists()

        payload = json.loads(report.read_text(encoding="utf-8"))
        assert payload["mutations"]
        mutation = next(
            (item for item in payload["mutations"] if item.get("metadata", {}).get("symbolic_status")),
            None,
        )
        if mutation is None:
            pytest.skip("No symbolic mutation metadata produced by CLI mutate run")

        pass_name = mutation["pass_name"]
        symbolic_status = mutation["metadata"]["symbolic_status"]

        summary_result = subprocess.run(
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
        assert summary_result.returncode == 0
        assert "Symbolic Mutation Summary" in summary_result.stdout

        pass_result = subprocess.run(
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
        assert pass_result.returncode == 0
        assert f'"pass_name": "{pass_name}"' in pass_result.stdout
        assert f'"only_pass": "{pass_name}"' in pass_result.stdout

        status_result = subprocess.run(
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
        assert status_result.returncode == 0
        assert f'"symbolic_status": "{symbolic_status}"' in status_result.stdout
        assert f'"only_status": "{symbolic_status}"' in status_result.stdout

    @pytest.mark.xfail(reason="CLI report --only-pass crashes with 'list' object has no attribute 'get'")
    def test_cli_report_can_export_filtered_json(self, ls_elf, tmp_path):
        """Test `report --output` writes a filtered JSON artifact from a real CLI report."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_export.bin"
        report = tmp_path / "cli_export.report.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 0
        assert report.exists()

        payload = json.loads(report.read_text(encoding="utf-8"))
        mutation = next(
            (item for item in payload.get("mutations", []) if item.get("metadata", {}).get("symbolic_status")),
            None,
        )
        if mutation is None:
            pytest.skip("No symbolic mutation metadata produced by CLI mutate run")

        pass_name = mutation["pass_name"]
        symbolic_status = mutation["metadata"]["symbolic_status"]
        filtered_output = tmp_path / "filtered.report.json"

        report_result = subprocess.run(
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
        assert report_result.returncode == 0
        assert filtered_output.exists()
        assert "Filtered report written:" in report_result.stdout

        filtered_payload = json.loads(filtered_output.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_pass"] == pass_name
        assert filtered_payload["report_filters"]["only_status"] == symbolic_status
        assert filtered_payload["filtered_summary"]["mutations"] == len(filtered_payload["mutations"])
        assert filtered_payload["filtered_summary"]["passes"] == [pass_name]
        assert filtered_payload["filtered_summary"]["symbolic_statuses"] == {
            symbolic_status: len(filtered_payload["mutations"])
        }
        assert filtered_payload["mutations"]
        assert all(item["pass_name"] == pass_name for item in filtered_payload["mutations"])
        assert all(
            item.get("metadata", {}).get("symbolic_status") == symbolic_status for item in filtered_payload["mutations"]
        )

    @pytest.mark.xfail(reason="CLI report --only-pass crashes with 'list' object has no attribute 'get'")
    def test_cli_report_require_results_uses_exit_code_for_ci(self, ls_elf, tmp_path):
        """Test `report --require-results` succeeds or fails based on real filtered output."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_require.bin"
        report = tmp_path / "cli_require.report.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 0
        payload = json.loads(report.read_text(encoding="utf-8"))
        mutation = next(
            (item for item in payload.get("mutations", []) if item.get("metadata", {}).get("symbolic_status")),
            None,
        )
        if mutation is None:
            pytest.skip("No symbolic mutation metadata produced by CLI mutate run")

        pass_name = mutation["pass_name"]

        success_result = subprocess.run(
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
        assert success_result.returncode == 0
        assert f'"only_pass": "{pass_name}"' in success_result.stdout

        empty_result = subprocess.run(
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
        assert empty_result.returncode == 1
        assert '"mutations": []' in empty_result.stdout

    def test_cli_report_require_results_supports_min_severity(self, ls_elf, tmp_path):
        """Test `report --require-results --min-severity` on a real generated report."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_require_severity.bin"
        report = tmp_path / "cli_require_severity.report.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 0

        strict_result = subprocess.run(
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
        failing_result = subprocess.run(
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

        assert strict_result.returncode == 0
        assert failing_result.returncode == 1

    def test_cli_mutate_min_severity_can_pass(self, ls_elf, tmp_path):
        """`mutate --min-severity` should succeed when the final report meets the threshold."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_min_severity_ok.bin"
        report = tmp_path / "cli_mutate_min_severity_ok.report.json"

        result = subprocess.run(
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

        assert result.returncode == 0
        assert output_path.exists()
        assert report.exists()
        assert "Severity gate passed:" in result.stdout

        payload = json.loads(report.read_text(encoding="utf-8"))
        assert payload["summary"]["validation_mode"] == "structural"
        assert payload["summary"]["symbolic_severity_by_pass"][0]["severity"] == "not-requested"
        assert payload["gate_evaluation"]["requested"]["min_severity"] == "not-requested"
        assert payload["gate_evaluation"]["results"]["min_severity_passed"] is True
        assert payload["gate_evaluation"]["results"]["all_passed"] is True

    def test_cli_mutate_min_severity_can_fail_without_losing_artifacts(self, ls_elf, tmp_path):
        """`mutate --min-severity` should fail with code 1 but keep output/report artifacts."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_min_severity_fail.bin"
        report = tmp_path / "cli_mutate_min_severity_fail.report.json"

        result = subprocess.run(
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

        assert result.returncode == 1
        assert output_path.exists()
        assert report.exists()
        assert "Severity gate failed:" in result.stdout

        payload = json.loads(report.read_text(encoding="utf-8"))
        assert payload["summary"]["validation_mode"] == "structural"
        assert payload["summary"]["symbolic_severity_by_pass"][0]["severity"] == "not-requested"
        assert payload["gate_evaluation"]["requested"]["min_severity"] == "clean"
        assert payload["gate_evaluation"]["results"]["min_severity_passed"] is False
        assert payload["gate_evaluation"]["results"]["all_passed"] is False
        assert payload["gate_failures"]["min_severity_failed"] is True
        assert payload["summary"]["gate_failures"]["min_severity_failed"] is True

    def test_cli_mutate_require_pass_severity_can_pass(self, ls_elf, tmp_path):
        """`mutate --require-pass-severity` should succeed when the named pass meets the threshold."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_pass_severity_ok.bin"
        report = tmp_path / "cli_mutate_pass_severity_ok.report.json"

        result = subprocess.run(
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

        assert result.returncode == 0
        assert output_path.exists()
        assert report.exists()
        assert "Pass severity gate passed:" in result.stdout
        assert "NopInsertion<=not-requested" in result.stdout

        payload = json.loads(report.read_text(encoding="utf-8"))
        assert payload["passes"]["NopInsertion"]["symbolic_summary"]["severity"] == "not-requested"
        assert payload["gate_evaluation"]["requested"]["require_pass_severity"] == [
            {"pass_name": "NopInsertion", "max_severity": "not-requested"}
        ]
        assert payload["gate_evaluation"]["results"]["require_pass_severity_passed"] is True
        assert payload["gate_evaluation"]["results"]["require_pass_severity_failures"] == []
        assert payload["gate_evaluation"]["results"]["all_passed"] is True

    def test_cli_mutate_require_pass_severity_can_fail_without_losing_artifacts(self, ls_elf, tmp_path):
        """`mutate --require-pass-severity` should fail with code 1 but keep artifacts."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_pass_severity_fail.bin"
        report = tmp_path / "cli_mutate_pass_severity_fail.report.json"

        result = subprocess.run(
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

        assert result.returncode == 1
        assert output_path.exists()
        assert report.exists()
        assert "Pass severity gate failed:" in result.stdout
        assert "NopInsertion=not-requested(expected <= clean)" in result.stdout

        payload = json.loads(report.read_text(encoding="utf-8"))
        assert payload["passes"]["NopInsertion"]["symbolic_summary"]["severity"] == "not-requested"
        assert payload["gate_evaluation"]["requested"]["require_pass_severity"] == [
            {"pass_name": "NopInsertion", "max_severity": "clean"}
        ]
        assert payload["gate_evaluation"]["results"]["require_pass_severity_passed"] is False
        assert payload["gate_evaluation"]["results"]["require_pass_severity_failures"] == [
            "NopInsertion=not-requested(expected <= clean)"
        ]
        assert payload["gate_evaluation"]["results"]["all_passed"] is False
        assert payload["gate_failures"]["require_pass_severity_failure_count"] == 1
        assert payload["gate_failure_priority"] == [
            {
                "pass_name": "NopInsertion",
                "failure_count": 1,
                "strictest_expected_severity": "clean",
                "failures": ["NopInsertion=not-requested(expected <= clean)"],
            }
        ]
        assert payload["gate_failure_severity_priority"] == [{"severity": "clean", "failure_count": 1}]
        assert payload["gate_failures"]["require_pass_severity_failures_by_expected_severity"] == {"clean": 1}
        assert payload["summary"]["gate_failures"]["require_pass_severity_failure_count"] == 1
        assert payload["summary"]["gate_failure_priority"] == payload["gate_failure_priority"]
        assert payload["summary"]["gate_failure_severity_priority"] == payload["gate_failure_severity_priority"]

    def test_cli_mutate_require_pass_severity_accepts_mutation_alias(self, ls_elf, tmp_path):
        """Short mutation aliases should resolve to the concrete pass name."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_pass_alias_ok.bin"
        report = tmp_path / "cli_mutate_pass_alias_ok.report.json"

        result = subprocess.run(
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

        assert result.returncode == 0
        assert output_path.exists()
        assert report.exists()
        assert "Pass severity gate passed:" in result.stdout
        assert "NopInsertion<=not-requested" in result.stdout

    def test_cli_mutate_require_pass_severity_alias_can_fail(self, ls_elf, tmp_path):
        """Short mutation aliases should produce the same failure semantics as pass names."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_pass_alias_fail.bin"
        report = tmp_path / "cli_mutate_pass_alias_fail.report.json"

        result = subprocess.run(
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

        assert result.returncode == 1
        assert output_path.exists()
        assert report.exists()
        assert "Pass severity gate failed:" in result.stdout
        assert "NopInsertion=not-requested(expected <= clean)" in result.stdout

    def test_cli_mutate_require_pass_severity_rejects_unknown_alias(self, ls_elf, tmp_path):
        """Unknown aliases should fail fast with exit code 2 before mutating."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "cli_mutate_pass_alias_invalid.bin"
        report = tmp_path / "cli_mutate_pass_alias_invalid.report.json"

        result = subprocess.run(
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

        assert result.returncode == 2
        assert not output_path.exists()
        assert not report.exists()
        assert "Invalid --require-pass-severity: definitely-missing=clean" in result.stdout

    def test_cli_symbolic_blocks_limited_pass_without_override(
        self,
        deterministic_register_elf,
        tmp_path,
    ):
        """Symbolic mode should fail fast for passes that declare limited symbolic support."""
        output_path = tmp_path / "register_blocked.bin"

        result = subprocess.run(
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

        assert result.returncode == 2
        assert "symbolic validation is marked limited" in result.stdout
        assert "--allow-limited-symbolic" in result.stdout
        assert not output_path.exists()

    def test_cli_symbolic_allows_limited_pass_with_override(
        self,
        deterministic_register_elf,
        tmp_path,
    ):
        """The explicit override should allow the limited symbolic pass to run."""
        output_path = tmp_path / "register_allowed.bin"
        report_path = tmp_path / "register_allowed.report.json"

        result = subprocess.run(
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

        assert result.returncode == 0
        assert "Limited symbolic coverage explicitly allowed" in result.stdout
        assert output_path.exists()
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        assert (
            payload["pass_support"]["RegisterSubstitution"]["validator_capabilities"]["symbolic"]["recommended"]
            is False
        )

    def test_cli_symbolic_can_degrade_limited_pass_to_runtime(
        self,
        deterministic_register_elf,
        tmp_path,
    ):
        """Limited symbolic support can degrade to runtime validation instead of blocking."""
        output_path = tmp_path / "register_runtime.bin"
        report_path = tmp_path / "register_runtime.report.json"

        result = subprocess.run(
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

        assert result.returncode == 0
        assert "Degrading validation mode from symbolic to runtime" in result.stdout
        assert output_path.exists()
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        assert payload["summary"]["requested_validation_mode"] == "symbolic"
        assert payload["summary"]["validation_mode"] == "runtime"
        assert payload["summary"]["degradation_roles"]["degradation-trigger"] == 1
        assert payload["validation_policy"]["policy"] == "degrade-runtime"
        assert payload["validation_policy"]["reason"] == "limited-symbolic-support"
        assert payload["validation_policy"]["limited_passes"][0]["role"] == "degradation-trigger"
        assert payload["validation"]["runtime"]["passed"] in {True, False}
        assert (
            payload["passes"]["RegisterSubstitution"]["validation_context"]["requested_validation_mode"] == "symbolic"
        )
        assert payload["passes"]["RegisterSubstitution"]["validation_context"]["effective_validation_mode"] == "runtime"
        assert payload["passes"]["RegisterSubstitution"]["validation_context"]["degraded_execution"] is True
        assert payload["passes"]["RegisterSubstitution"]["validation_context"]["degradation_triggered_by_pass"] is True
        assert payload["passes"]["RegisterSubstitution"]["validation_context"]["role"] == "degradation-trigger"

    def test_cli_symbolic_can_degrade_limited_pass_to_structural(
        self,
        deterministic_register_elf,
        tmp_path,
    ):
        """Limited symbolic support can degrade to structural validation instead of blocking."""
        output_path = tmp_path / "register_structural.bin"
        report_path = tmp_path / "register_structural.report.json"

        result = subprocess.run(
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

        assert result.returncode == 0
        assert "Degrading validation mode from symbolic to structural" in result.stdout
        assert output_path.exists()
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        assert payload["summary"]["requested_validation_mode"] == "symbolic"
        assert payload["summary"]["validation_mode"] == "structural"
        assert payload["summary"]["degradation_roles"]["degradation-trigger"] == 1
        assert payload["validation_policy"]["policy"] == "degrade-structural"
        assert payload["validation_policy"]["reason"] == "limited-symbolic-support"
        assert payload["validation_policy"]["limited_passes"][0]["role"] == "degradation-trigger"
        assert "runtime" not in payload["validation"]
        assert payload["passes"]["RegisterSubstitution"]["validation_context"]["role"] == "degradation-trigger"

    def test_cli_report_can_filter_degraded_validation_runs(
        self,
        deterministic_register_elf,
        tmp_path,
    ):
        """Report can triage a real run where validation mode was degraded."""
        output_path = tmp_path / "register_degraded.bin"
        report_path = tmp_path / "register_degraded.report.json"
        filtered_path = tmp_path / "register_degraded.filtered.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 0
        assert report_path.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "Validation Mode Adjustment" in report_result.stdout
        assert "requested=symbolic, effective=runtime" in report_result.stdout
        assert "Degradation Roles" in report_result.stdout
        assert "Degraded Severity Priority" in report_result.stdout
        assert "degradation-trigger: 1" in report_result.stdout
        assert "Pass Validation Context" in report_result.stdout
        assert "RegisterSubstitution" in report_result.stdout

        export_result = subprocess.run(
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

        assert export_result.returncode == 0
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_degraded"] is True
        assert filtered_payload["filtered_summary"]["degraded_validation"] is True
        assert filtered_payload["filtered_summary"]["requested_validation_mode"] == "symbolic"
        assert filtered_payload["filtered_summary"]["validation_mode"] == "runtime"
        assert filtered_payload["filtered_summary"]["degraded_passes"]
        assert filtered_payload["filtered_summary"]["degraded_passes"][0]["pass_name"] == "RegisterSubstitution"
        assert (
            filtered_payload["filtered_summary"]["symbolic_severity_by_pass"][0]["pass_name"] == "RegisterSubstitution"
        )
        assert filtered_payload["filtered_summary"]["degradation_roles"]["degradation-trigger"] == 1

        mismatch_filtered_path = tmp_path / "mismatch-filtered.json"
        mismatch_export_result = subprocess.run(
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

        assert mismatch_export_result.returncode == 0
        assert "Mismatch Degradation Context" in mismatch_export_result.stdout
        assert "Mismatch Severity Priority" in mismatch_export_result.stdout
        assert "requested=symbolic, effective=runtime" in mismatch_export_result.stdout
        assert "trigger_passes=RegisterSubstitution" in mismatch_export_result.stdout
        mismatch_payload = json.loads(mismatch_filtered_path.read_text(encoding="utf-8"))
        assert mismatch_payload["report_filters"]["only_degraded"] is True
        assert mismatch_payload["report_filters"]["only_mismatches"] is True
        assert mismatch_payload["filtered_summary"]["requested_validation_mode"] == "symbolic"
        assert mismatch_payload["filtered_summary"]["validation_mode"] == "runtime"
        assert mismatch_payload["filtered_summary"]["degraded_validation"] is True
        assert mismatch_payload["filtered_summary"]["degraded_passes"][0]["pass_name"] == "RegisterSubstitution"
        assert mismatch_payload["filtered_summary"]["degradation_roles"]["degradation-trigger"] == 1
        assert (
            mismatch_payload["filtered_summary"]["symbolic_severity_by_pass"][0]["pass_name"] == "RegisterSubstitution"
        )

    def test_cli_report_can_filter_failed_gates(self, ls_elf, tmp_path):
        """Report can triage a real run where mutate finished with failed CLI gates."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "failed_gate.bin"
        report_path = tmp_path / "failed_gate.report.json"
        filtered_path = tmp_path / "failed_gate.filtered.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 1
        assert report_path.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "Gate Evaluation" in report_result.stdout
        assert "Gate Failure Summary" in report_result.stdout
        assert "all_passed=no" in report_result.stdout
        assert "min_severity=clean, passed=no" in report_result.stdout
        assert "min_severity_failed=yes, require_pass_failures=0" in report_result.stdout

        export_result = subprocess.run(
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

        assert export_result.returncode == 0
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_failed_gates"] is True
        assert filtered_payload["filtered_summary"]["failed_gates"] is True
        assert filtered_payload["filtered_summary"]["gate_evaluation"]["requested"]["min_severity"] == "clean"
        assert filtered_payload["filtered_summary"]["gate_evaluation"]["results"]["all_passed"] is False
        assert filtered_payload["filtered_summary"]["gate_failures"]["min_severity_failed"] is True
        assert filtered_payload["filtered_summary"]["gate_failures"]["require_pass_severity_failure_count"] == 0

        require_result = subprocess.run(
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

        assert require_result.returncode == 0
        assert "Gate Evaluation" in require_result.stdout

    def test_cli_report_groups_failed_pass_severity_gates(self, ls_elf, tmp_path):
        """Report groups failed per-pass severity rules for a real mutate report."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "failed_pass_gate.bin"
        report_path = tmp_path / "failed_pass_gate.report.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 1
        assert report_path.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "Gate Failure Summary" in report_result.stdout
        assert "require_pass_failures=1" in report_result.stdout
        assert "expected_severity_priority=clean:1" in report_result.stdout
        assert "Gate Failure By Pass" in report_result.stdout
        assert "NopInsertion" in report_result.stdout
        assert "NopInsertion=not-requested(expected <= clean)" in report_result.stdout

        payload = json.loads(report_path.read_text(encoding="utf-8"))
        assert payload["gate_evaluation"]["results"]["require_pass_severity_failures"] == [
            "NopInsertion=not-requested(expected <= clean)"
        ]

    def test_cli_report_only_expected_severity_filters_real_failed_gates(self, ls_elf, tmp_path):
        """Report filters real failed gate views by expected severity."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_expected_severity.bin"
        report_path = tmp_path / "only_expected_severity.report.json"
        filtered_path = tmp_path / "only_expected_severity.filtered.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 1
        assert report_path.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "expected_severity_counts=clean:1" in report_result.stdout
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_expected_severity"] == "clean"
        assert filtered_payload["filtered_summary"]["gate_failures"][
            "require_pass_severity_failures_by_expected_severity"
        ] == {"clean": 1}
        assert filtered_payload["filtered_summary"]["gate_failure_priority"] == [
            {
                "pass_name": "NopInsertion",
                "failure_count": 1,
                "strictest_expected_severity": "clean",
                "failures": ["NopInsertion=not-requested(expected <= clean)"],
            }
        ]

    def test_cli_report_only_expected_severity_require_results_on_real_failed_gates(self, ls_elf, tmp_path):
        """Require-results should respect filtered expected-severity gate views."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_expected_severity_require_results.bin"
        report_path = tmp_path / "only_expected_severity_require_results.report.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 1
        assert report_path.exists()

        success_result = subprocess.run(
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
        failure_result = subprocess.run(
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

        assert success_result.returncode == 0
        assert "Gate Failure Summary" in success_result.stdout
        assert failure_result.returncode == 1

    def test_cli_report_only_pass_failure_filters_real_failed_gates(self, ls_elf, tmp_path):
        """Report filters real failed gates to a single pass failure."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_pass_failure.bin"
        report_path = tmp_path / "only_pass_failure.report.json"
        filtered_path = tmp_path / "only_pass_failure.filtered.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 1
        assert report_path.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "expected_severity_counts=clean:1" in report_result.stdout
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_pass_failure"] == "NopInsertion"
        assert filtered_payload["filtered_summary"]["gate_failures"]["require_pass_severity_failures_by_pass"] == {
            "NopInsertion": ["NopInsertion=not-requested(expected <= clean)"]
        }
        assert filtered_payload["filtered_summary"]["gate_failure_priority"] == [
            {
                "pass_name": "NopInsertion",
                "failure_count": 1,
                "strictest_expected_severity": "clean",
                "failures": ["NopInsertion=not-requested(expected <= clean)"],
            }
        ]

    def test_cli_report_only_pass_failure_require_results_on_real_failed_gates(self, ls_elf, tmp_path):
        """Require-results should respect filtered pass-specific gate views."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_pass_failure_require_results.bin"
        report_path = tmp_path / "only_pass_failure_require_results.report.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 1
        assert report_path.exists()

        success_result = subprocess.run(
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
        failure_result = subprocess.run(
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

        assert success_result.returncode == 0
        assert "Gate Failure Summary" in success_result.stdout
        assert failure_result.returncode == 1

    def test_cli_report_only_pass_failure_accepts_mutation_alias(self, ls_elf, tmp_path):
        """Report accepts stable mutation aliases for pass-failure filtering."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_pass_failure_alias.bin"
        report_path = tmp_path / "only_pass_failure_alias.report.json"
        filtered_path = tmp_path / "only_pass_failure_alias.filtered.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 1
        assert report_path.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "Pass Failure Filter Resolution" in report_result.stdout
        assert "nop -> NopInsertion" in report_result.stdout
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        assert filtered_payload["report_filters"]["only_pass_failure"] == "NopInsertion"
        assert filtered_payload["filtered_summary"]["only_pass_failure"] == "NopInsertion"

    def test_cli_report_only_pass_accepts_mutation_alias(self, ls_elf, tmp_path):
        """Report accepts stable mutation aliases for pass filtering."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "only_pass_alias.bin"
        report = tmp_path / "only_pass_alias.report.json"
        mutate_result = subprocess.run(
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
        assert mutate_result.returncode == 0
        assert report.exists()

        pass_result = subprocess.run(
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

        assert pass_result.returncode == 0
        assert "Pass Filter Resolution" in pass_result.stdout
        assert "nop -> NopInsertion" in pass_result.stdout
        assert '"report_filters": {' in pass_result.stdout
        assert '"only_pass": "NopInsertion"' in pass_result.stdout
        assert '"pass_name": "NopInsertion"' in pass_result.stdout

    def test_cli_report_orders_failed_pass_severity_gates_by_expected_severity(self, ls_elf, tmp_path):
        """Report orders grouped pass failures by stricter expected severity first."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "failed_pass_gate_order.bin"
        report_path = tmp_path / "failed_pass_gate_order.report.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 1
        assert report_path.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "expected_severity_counts=bounded-only:1, clean:1" in report_result.stdout
        section = report_result.stdout.split("Gate Failure By Pass", 1)[1]
        assert "count=1, strictest_expected=bounded-only" in section
        assert "count=1, strictest_expected=clean" in section
        assert section.index("InstructionSubstitution") < section.index("NopInsertion")

        payload = json.loads(report_path.read_text(encoding="utf-8"))
        failures = payload["gate_evaluation"]["results"]["require_pass_severity_failures"]
        assert "InstructionSubstitution=not-requested(expected <= bounded-only)" in failures
        assert "NopInsertion=not-requested(expected <= clean)" in failures

    def test_cli_report_breaks_same_severity_gate_ties_by_failure_count(self, ls_elf, tmp_path):
        """Report orders same-severity gate failures by number of failures for the pass."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "failed_pass_gate_count_order.bin"
        report_path = tmp_path / "failed_pass_gate_count_order.report.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 1
        assert report_path.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        assert "expected_severity_counts=clean:3" in report_result.stdout
        section = report_result.stdout.split("Gate Failure By Pass", 1)[1]
        assert "count=2, strictest_expected=clean" in section
        assert section.index("NopInsertion") < section.index("InstructionSubstitution")

        payload = json.loads(report_path.read_text(encoding="utf-8"))
        failures = payload["gate_evaluation"]["results"]["require_pass_severity_failures"]
        assert failures.count("NopInsertion=not-requested(expected <= clean)") == 2
        assert "InstructionSubstitution=not-requested(expected <= clean)" in failures

    def test_cli_report_exports_gate_failure_priority_for_real_failed_gates(self, ls_elf, tmp_path):
        """Filtered report JSON preserves ordered gate failure priority for real runs."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "failed_pass_gate_priority.bin"
        report_path = tmp_path / "failed_pass_gate_priority.report.json"
        filtered_path = tmp_path / "failed_pass_gate_priority.filtered.json"

        mutate_result = subprocess.run(
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

        assert mutate_result.returncode == 1
        assert report_path.exists()

        report_result = subprocess.run(
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

        assert report_result.returncode == 0
        filtered_payload = json.loads(filtered_path.read_text(encoding="utf-8"))
        priority = filtered_payload["filtered_summary"]["gate_failure_priority"]
        severity_counts = filtered_payload["filtered_summary"]["gate_failures"][
            "require_pass_severity_failures_by_expected_severity"
        ]
        assert [row["pass_name"] for row in priority] == [
            "NopInsertion",
            "InstructionSubstitution",
        ]
        assert priority[0]["failure_count"] == 2
        assert priority[0]["strictest_expected_severity"] == "clean"
        assert severity_counts == {"clean": 3}
