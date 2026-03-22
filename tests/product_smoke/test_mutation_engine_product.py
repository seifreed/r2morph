from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.mutations import NopInsertionPass
from r2morph.mutations.base import MutationPass
from r2morph.validation import BinaryValidator


if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


pytestmark = [pytest.mark.product_smoke]


class _ForcedRollbackPass(MutationPass):
    def __init__(self):
        super().__init__("ForcedRollback")

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
            mutation_kind="forced_rollback",
            metadata={"test": "forced_rollback"},
        )
        return {"mutations_applied": 1}


@pytest.mark.slow
def test_product_mutate_generates_stable_report(stable_elf_binary: Path, tmp_path: Path):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    output = tmp_path / "mutated.bin"
    report = tmp_path / "mutated.report.json"

    with MorphEngine() as engine:
        engine.load_binary(stable_elf_binary).analyze()
        engine.add_mutation(NopInsertionPass(config={"probability": 0.4}))
        result = engine.run(validation_mode="structural", report_path=report)
        engine.save(output)

    assert output.exists()
    assert report.exists()
    assert result["validation"]["all_passed"] in {True, False}

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert set(payload.keys()) >= {
        "input",
        "output",
        "passes",
        "mutations",
        "validation",
        "summary",
        "config",
        "support_matrix",
    }
    assert payload["support_matrix"]["stable_mutations"] == ["nop", "substitute", "register"]


@pytest.mark.slow
def test_product_symbolic_validation_report_is_explicit(
    stable_elf_binary: Path,
    tmp_path: Path,
):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    report = tmp_path / "symbolic.report.json"
    output = tmp_path / "symbolic.bin"

    with MorphEngine() as engine:
        engine.load_binary(stable_elf_binary).analyze()
        engine.add_mutation(_ForcedRollbackPass())
        result = engine.run(validation_mode="symbolic", report_path=report)
        engine.save(output)

    assert report.exists()
    assert result["validation_mode"] == "symbolic"

    payload = json.loads(report.read_text(encoding="utf-8"))
    symbolic = payload["validation"]["symbolic"]
    assert symbolic["requested"] is True
    assert isinstance(symbolic["statuses"], list)
    assert symbolic["statuses"]
    assert symbolic["statuses"][0]["pass_name"] == "ForcedRollback"


@pytest.mark.slow
def test_product_symbolic_report_keeps_mutation_level_metadata(
    stable_elf_binary: Path,
    tmp_path: Path,
):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    report = tmp_path / "symbolic-mutation.report.json"

    with MorphEngine() as engine:
        engine.load_binary(stable_elf_binary).analyze()
        engine.add_mutation(_ForcedRollbackPass())
        result = engine.run(validation_mode="symbolic", report_path=report)

    assert result["validation_mode"] == "symbolic"
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["mutations"]
    mutation = payload["mutations"][0]
    assert mutation["metadata"]["symbolic_requested"] is True
    assert "symbolic_status" in mutation["metadata"]


@pytest.mark.slow
@pytest.mark.parametrize(
    ("mutation", "expected_pass"),
    [
        ("nop", "NopInsertion"),
        ("substitute", "InstructionSubstitution"),
        ("register", "RegisterSubstitution"),
    ],
)
def test_product_cli_accepts_each_stable_pass(
    stable_elf_binary: Path,
    tmp_path: Path,
    mutation: str,
    expected_pass: str,
):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    output = tmp_path / f"{mutation}.bin"
    report = tmp_path / f"{mutation}.report.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "r2morph.cli",
            "mutate",
            str(stable_elf_binary),
            "-o",
            str(output),
            "--report",
            str(report),
            "--seed",
            "1337",
            "-m",
            mutation,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0
    assert output.exists()
    assert report.exists()

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["config"]["seed"] == 1337
    assert payload["summary"]["passes_run"] == 1
    assert expected_pass in payload["passes"]


def _normalize_passes_for_comparison(passes: dict) -> dict:
    """Remove non-deterministic fields from passes for reproducibility comparison."""
    normalized = {}
    for pass_name, pass_data in passes.items():
        normalized[pass_name] = {
            k: v for k, v in pass_data.items() if k not in ("execution_time_seconds", "previous_binary_path")
        }
        # Normalize mutations within pass
        if "mutations" in normalized[pass_name]:
            normalized[pass_name]["mutations"] = _normalize_mutations_for_comparison(normalized[pass_name]["mutations"])
    return normalized


def _normalize_mutations_for_comparison(mutations: list) -> list:
    """Remove non-deterministic fields from mutations for reproducibility comparison."""
    normalized = []
    for mutation in mutations:
        normalized_mutation = {k: v for k, v in mutation.items() if k not in ("recorded_after_seconds",)}
        normalized.append(normalized_mutation)
    return normalized


def _normalize_summary_for_comparison(summary: dict) -> dict:
    """Remove non-deterministic fields from summary for reproducibility comparison."""
    result = dict(summary)
    result.pop("execution_time_seconds", None)
    return result


@pytest.mark.slow
def test_product_seed_is_reproducible_for_stable_pass(
    stable_elf_binary: Path,
    tmp_path: Path,
):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    report_a = tmp_path / "seed_a.report.json"
    out_a = tmp_path / "seed_a.bin"
    report_b = tmp_path / "seed_b.report.json"
    out_b = tmp_path / "seed_b.bin"

    base_cmd = [
        sys.executable,
        "-m",
        "r2morph.cli",
        "mutate",
        str(stable_elf_binary),
        "--seed",
        "2026",
        "-m",
        "nop",
    ]

    first = subprocess.run(
        [*base_cmd, "-o", str(out_a), "--report", str(report_a)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    second = subprocess.run(
        [*base_cmd, "-o", str(out_b), "--report", str(report_b)],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert first.returncode == 0
    assert second.returncode == 0

    payload_a = json.loads(report_a.read_text(encoding="utf-8"))
    payload_b = json.loads(report_b.read_text(encoding="utf-8"))

    assert payload_a["config"]["seed"] == 2026
    assert _normalize_mutations_for_comparison(payload_a["mutations"]) == _normalize_mutations_for_comparison(
        payload_b["mutations"]
    )
    assert _normalize_passes_for_comparison(payload_a["passes"]) == _normalize_passes_for_comparison(
        payload_b["passes"]
    )

    out_a_bytes = out_a.read_bytes()
    out_b_bytes = out_b.read_bytes()
    assert out_a_bytes == out_b_bytes, "Binary output should be byte-identical for same seed"


@pytest.mark.slow
@pytest.mark.parametrize("mutation", ["nop", "substitute", "register"])
def test_product_seed_is_reproducible_for_all_stable_passes(
    stable_elf_binary: Path,
    tmp_path: Path,
    mutation: str,
):
    """Each stable mutation pass should produce identical output for same seed."""
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    report_a = tmp_path / f"seed_{mutation}_a.report.json"
    out_a = tmp_path / f"seed_{mutation}_a.bin"
    report_b = tmp_path / f"seed_{mutation}_b.report.json"
    out_b = tmp_path / f"seed_{mutation}_b.bin"

    seed = 42

    base_cmd = [
        sys.executable,
        "-m",
        "r2morph.cli",
        "mutate",
        str(stable_elf_binary),
        "--seed",
        str(seed),
        "-m",
        mutation,
    ]

    first = subprocess.run(
        [*base_cmd, "-o", str(out_a), "--report", str(report_a)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    second = subprocess.run(
        [*base_cmd, "-o", str(out_b), "--report", str(report_b)],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert first.returncode == 0, f"First run failed: {first.stderr}"
    assert second.returncode == 0, f"Second run failed: {second.stderr}"

    payload_a = json.loads(report_a.read_text(encoding="utf-8"))
    payload_b = json.loads(report_b.read_text(encoding="utf-8"))

    assert payload_a["config"]["seed"] == seed
    assert _normalize_mutations_for_comparison(payload_a["mutations"]) == _normalize_mutations_for_comparison(
        payload_b["mutations"]
    ), f"Mutations differ for {mutation}"
    assert _normalize_passes_for_comparison(payload_a["passes"]) == _normalize_passes_for_comparison(
        payload_b["passes"]
    ), f"Passes differ for {mutation}"

    out_a_bytes = out_a.read_bytes()
    out_b_bytes = out_b.read_bytes()
    assert out_a_bytes == out_b_bytes, f"Binary output should be byte-identical for {mutation} with same seed"


@pytest.mark.slow
def test_product_seed_is_reproducible_for_combined_stable_passes(
    stable_elf_binary: Path,
    tmp_path: Path,
):
    """Combined stable mutations should produce identical output for same seed."""
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    report_a = tmp_path / "seed_combined_a.report.json"
    out_a = tmp_path / "seed_combined_a.bin"
    report_b = tmp_path / "seed_combined_b.report.json"
    out_b = tmp_path / "seed_combined_b.bin"

    seed = 999
    base_cmd = [
        sys.executable,
        "-m",
        "r2morph.cli",
        "mutate",
        str(stable_elf_binary),
        "--seed",
        str(seed),
        "-m",
        "nop",
        "-m",
        "substitute",
        "-m",
        "register",
    ]

    first = subprocess.run(
        [*base_cmd, "-o", str(out_a), "--report", str(report_a)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    second = subprocess.run(
        [*base_cmd, "-o", str(out_b), "--report", str(report_b)],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert first.returncode == 0, f"First run failed: {first.stderr}"
    assert second.returncode == 0, f"Second run failed: {second.stderr}"

    payload_a = json.loads(report_a.read_text(encoding="utf-8"))
    payload_b = json.loads(report_b.read_text(encoding="utf-8"))

    assert payload_a["config"]["seed"] == seed
    assert _normalize_mutations_for_comparison(payload_a["mutations"]) == _normalize_mutations_for_comparison(
        payload_b["mutations"]
    ), "Mutations differ for combined passes"
    assert _normalize_passes_for_comparison(payload_a["passes"]) == _normalize_passes_for_comparison(
        payload_b["passes"]
    ), "Passes differ for combined passes"

    out_a_bytes = out_a.read_bytes()
    out_b_bytes = out_b.read_bytes()
    assert out_a_bytes == out_b_bytes, "Binary output should be byte-identical for combined passes with same seed"


@pytest.mark.slow
def test_product_runtime_validation_with_corpus(
    stable_elf_binary: Path,
    stable_runtime_corpus: list[dict[str, object]],
    tmp_path: Path,
):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    output = tmp_path / "runtime.bin"

    with MorphEngine() as engine:
        engine.load_binary(stable_elf_binary).analyze()
        engine.add_mutation(NopInsertionPass(config={"probability": 0.4}))
        engine.run(validation_mode="structural")
        engine.save(output)

    validator = BinaryValidator(timeout=5)
    validator.load_test_cases(stable_runtime_corpus)
    result = validator.validate(stable_elf_binary, output)

    assert len(result.test_cases) == 2
    assert result.compared_signals["stdout"] is True
    assert result.similarity_score >= 0.0


@pytest.mark.slow
def test_product_cli_validate_with_canonical_corpus(
    stable_elf_binary: Path,
    stable_runtime_corpus_path: Path,
    tmp_path: Path,
):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    output = tmp_path / "runtime_cli.bin"

    with MorphEngine() as engine:
        engine.load_binary(stable_elf_binary).analyze()
        engine.add_mutation(NopInsertionPass(config={"probability": 0.4}))
        engine.run(validation_mode="structural")
        engine.save(output)

    validate_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "r2morph.cli",
            "validate",
            str(stable_elf_binary),
            str(output),
            "--corpus",
            str(stable_runtime_corpus_path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert validate_result.returncode in {0, 1}
    assert '"test_cases"' in validate_result.stdout
    assert '"description": "default-exec"' in validate_result.stdout


@pytest.mark.slow
def test_product_fail_fast_rolls_back_invalid_pass(
    stable_elf_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    from r2morph.validation.manager import ValidationIssue, ValidationOutcome, ValidationManager

    def _always_fail(self, binary, pass_result):
        return ValidationOutcome(
            validator_type="structural",
            passed=False,
            scope="pass",
            issues=[ValidationIssue(validator="test", message="forced failure")],
        )

    monkeypatch.setattr(ValidationManager, "validate_pass", _always_fail)

    output = tmp_path / "rolled_back.bin"

    with MorphEngine() as engine:
        engine.load_binary(stable_elf_binary).analyze()
        engine.add_mutation(_ForcedRollbackPass())
        with pytest.raises(RuntimeError):
            engine.run(validation_mode="structural", rollback_policy="fail-fast")
        engine.save(output)

    assert output.exists()
    assert output.read_bytes() == stable_elf_binary.read_bytes()


@pytest.mark.slow
def test_product_skip_invalid_pass_reports_discarded_mutations(
    stable_elf_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    from r2morph.validation.manager import ValidationIssue, ValidationOutcome, ValidationManager

    def _always_fail(self, binary, pass_result):
        return ValidationOutcome(
            validator_type="structural",
            passed=False,
            scope="pass",
            issues=[ValidationIssue(validator="test", message="forced failure")],
        )

    monkeypatch.setattr(ValidationManager, "validate_pass", _always_fail)

    report = tmp_path / "rollback.report.json"

    with MorphEngine() as engine:
        engine.load_binary(stable_elf_binary).analyze()
        engine.add_mutation(_ForcedRollbackPass())
        result = engine.run(
            validation_mode="structural",
            rollback_policy="skip-invalid-pass",
            report_path=report,
        )

    assert result["rolled_back_passes"] == 1
    assert result["discarded_mutations"] == 1
    assert result["pass_results"]["ForcedRollback"]["rollback_reason"] == "validation_failed"

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["summary"]["rolled_back_passes"] == 1
    assert payload["summary"]["discarded_mutations"] == 1


@pytest.mark.slow
def test_cli_mutate_validate_report_flow(stable_elf_binary: Path, tmp_path: Path):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    output = tmp_path / "cli_mutated.bin"
    report = tmp_path / "cli_mutated.report.json"

    mutate_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "r2morph.cli",
            "mutate",
            str(stable_elf_binary),
            "-o",
            str(output),
            "--report",
            str(report),
            "-m",
            "nop",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert mutate_result.returncode == 0
    assert output.exists()
    assert report.exists()

    validate_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "r2morph.cli",
            "validate",
            str(stable_elf_binary),
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert validate_result.returncode in {0, 1}
    assert '"similarity_score"' in validate_result.stdout

    report_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "r2morph.cli",
            "report",
            str(report),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert report_result.returncode == 0
    assert '"support_matrix"' in report_result.stdout
