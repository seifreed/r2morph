from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.core.engine_run import EngineRunOptions
from r2morph.mutations import NopInsertionPass
from r2morph.mutations.base import MutationPass
from r2morph.validation import BinaryValidator
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY
from tests.utils.process import run_command

_EXPECTED_LEN_RESULT_TEST_CASES_2 = 2
_EXPECTED_PAYLOAD_A_CONFIG_SEED_2026 = 2026
_EXPECTED_PAYLOAD_CONFIG_SEED_1337 = 1337


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
        result = engine.run(EngineRunOptions(validation_mode="structural", report_path=report))
        engine.save(output)

    expect(output.exists())
    expect(report.exists())
    expect(not (result["validation"]["all_passed"] not in {True, False}))

    payload = json.loads(report.read_text(encoding="utf-8"))
    expect(
        not (
            set(payload.keys())
            < {
                "input",
                "output",
                "passes",
                "mutations",
                "validation",
                "summary",
                "config",
                "support_matrix",
            }
        )
    )
    expect(payload["support_matrix"]["stable_mutations"] == ["nop", "substitute", "register"])


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
        result = engine.run(EngineRunOptions(validation_mode="symbolic", report_path=report))
        engine.save(output)

    expect(report.exists())
    expect(result["validation_mode"] == "symbolic")

    payload = json.loads(report.read_text(encoding="utf-8"))
    symbolic = payload["validation"]["symbolic"]
    expect(not (symbolic["requested"] is not True))
    expect(isinstance(symbolic["statuses"], list))
    expect(symbolic["statuses"])
    expect(symbolic["statuses"][0][MUTATION_NAME_KEY] == "ForcedRollback")


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
        result = engine.run(EngineRunOptions(validation_mode="symbolic", report_path=report))

    expect(result["validation_mode"] == "symbolic")
    payload = json.loads(report.read_text(encoding="utf-8"))
    expect(payload["mutations"])
    mutation = payload["mutations"][0]
    expect(not (mutation["metadata"]["symbolic_requested"] is not True))
    expect(not ("symbolic_status" not in mutation["metadata"]))


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

    result = run_command(
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

    expect(result.returncode == 0)
    expect(output.exists())
    expect(report.exists())

    payload = json.loads(report.read_text(encoding="utf-8"))
    expect(payload["config"]["seed"] == _EXPECTED_PAYLOAD_CONFIG_SEED_1337)
    expect(payload["summary"]["passes_run"] == 1)
    expect(not (expected_pass not in payload["passes"]))


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

    first = run_command(
        [*base_cmd, "-o", str(out_a), "--report", str(report_a)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    second = run_command(
        [*base_cmd, "-o", str(out_b), "--report", str(report_b)],
        capture_output=True,
        text=True,
        timeout=60,
    )

    expect(first.returncode == 0)
    expect(second.returncode == 0)

    payload_a = json.loads(report_a.read_text(encoding="utf-8"))
    payload_b = json.loads(report_b.read_text(encoding="utf-8"))

    expect(payload_a["config"]["seed"] == _EXPECTED_PAYLOAD_A_CONFIG_SEED_2026)
    expect(
        _normalize_mutations_for_comparison(payload_a["mutations"])
        == _normalize_mutations_for_comparison(payload_b["mutations"])
    )
    expect(
        _normalize_passes_for_comparison(payload_a["passes"]) == _normalize_passes_for_comparison(payload_b["passes"])
    )

    out_a_bytes = out_a.read_bytes()
    out_b_bytes = out_b.read_bytes()
    expect(out_a_bytes == out_b_bytes, "Binary output should be byte-identical for same seed")


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

    first = run_command(
        [*base_cmd, "-o", str(out_a), "--report", str(report_a)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    second = run_command(
        [*base_cmd, "-o", str(out_b), "--report", str(report_b)],
        capture_output=True,
        text=True,
        timeout=60,
    )

    expect(first.returncode == 0, f"First run failed: {first.stderr}")
    expect(second.returncode == 0, f"Second run failed: {second.stderr}")

    payload_a = json.loads(report_a.read_text(encoding="utf-8"))
    payload_b = json.loads(report_b.read_text(encoding="utf-8"))

    expect(payload_a["config"]["seed"] == seed)
    expect(
        _normalize_mutations_for_comparison(payload_a["mutations"])
        == _normalize_mutations_for_comparison(payload_b["mutations"]),
        f"Mutations differ for {mutation}",
    )
    expect(
        _normalize_passes_for_comparison(payload_a["passes"]) == _normalize_passes_for_comparison(payload_b["passes"]),
        f"Passes differ for {mutation}",
    )

    out_a_bytes = out_a.read_bytes()
    out_b_bytes = out_b.read_bytes()
    expect(out_a_bytes == out_b_bytes, f"Binary output should be byte-identical for {mutation} with same seed")


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

    first = run_command(
        [*base_cmd, "-o", str(out_a), "--report", str(report_a)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    second = run_command(
        [*base_cmd, "-o", str(out_b), "--report", str(report_b)],
        capture_output=True,
        text=True,
        timeout=120,
    )

    expect(first.returncode == 0, f"First run failed: {first.stderr}")
    expect(second.returncode == 0, f"Second run failed: {second.stderr}")

    payload_a = json.loads(report_a.read_text(encoding="utf-8"))
    payload_b = json.loads(report_b.read_text(encoding="utf-8"))

    expect(payload_a["config"]["seed"] == seed)
    expect(
        _normalize_mutations_for_comparison(payload_a["mutations"])
        == _normalize_mutations_for_comparison(payload_b["mutations"]),
        "Mutations differ for combined passes",
    )
    expect(
        _normalize_passes_for_comparison(payload_a["passes"]) == _normalize_passes_for_comparison(payload_b["passes"]),
        "Passes differ for combined passes",
    )

    out_a_bytes = out_a.read_bytes()
    out_b_bytes = out_b.read_bytes()
    expect(out_a_bytes == out_b_bytes, "Binary output should be byte-identical for combined passes with same seed")


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
        engine.run(EngineRunOptions(validation_mode="structural"))
        engine.save(output)

    validator = BinaryValidator(timeout=5)
    validator.load_test_cases(stable_runtime_corpus)
    result = validator.validate(stable_elf_binary, output)

    expect(len(result.test_cases) == _EXPECTED_LEN_RESULT_TEST_CASES_2)
    expect(not (result.compared_signals["stdout"] is not True))
    expect(not (result.similarity_score < 0.0))


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
        engine.run(EngineRunOptions(validation_mode="structural"))
        engine.save(output)

    validate_result = run_command(
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

    expect(not (validate_result.returncode not in {0, 1}))
    expect(not ('"test_cases"' not in validate_result.stdout))
    expect(not ('"description": "default-exec"' not in validate_result.stdout))


@pytest.mark.slow
def test_product_fail_fast_rolls_back_invalid_pass(
    stable_elf_binary: Path,
    tmp_path: Path,
):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    failing_validation_manager = importlib.import_module(
        "tests._doubles.failing_validation_manager"
    ).FailingValidationManager

    output = tmp_path / "rolled_back.bin"

    with MorphEngine() as engine:
        engine.load_binary(stable_elf_binary).analyze()
        engine.add_mutation(_ForcedRollbackPass())
        with pytest.raises(RuntimeError):
            engine.run(
                EngineRunOptions(
                    validation_mode="structural",
                    rollback_policy="fail-fast",
                    validation_manager=failing_validation_manager(),
                )
            )
        engine.save(output)

    expect(output.exists())
    expect(output.read_bytes() == stable_elf_binary.read_bytes())


@pytest.mark.slow
def test_product_skip_invalid_pass_reports_discarded_mutations(
    stable_elf_binary: Path,
    tmp_path: Path,
):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    failing_validation_manager = importlib.import_module(
        "tests._doubles.failing_validation_manager"
    ).FailingValidationManager

    report = tmp_path / "rollback.report.json"

    with MorphEngine() as engine:
        engine.load_binary(stable_elf_binary).analyze()
        engine.add_mutation(_ForcedRollbackPass())
        result = engine.run(
            EngineRunOptions(
                validation_mode="structural",
                rollback_policy="skip-invalid-pass",
                validation_manager=failing_validation_manager(),
                report_path=report,
            )
        )

    expect(result["rolled_back_passes"] == 1)
    expect(result["discarded_mutations"] == 1)
    expect(result["pass_results"]["ForcedRollback"]["rollback_reason"] == "validation_failed")

    payload = json.loads(report.read_text(encoding="utf-8"))
    expect(payload["summary"]["rolled_back_passes"] == 1)
    expect(payload["summary"]["discarded_mutations"] == 1)


@pytest.mark.slow
def test_cli_mutate_validate_report_flow(stable_elf_binary: Path, tmp_path: Path):
    if not stable_elf_binary.exists():
        pytest.skip("Stable ELF fixture not available")

    output = tmp_path / "cli_mutated.bin"
    report = tmp_path / "cli_mutated.report.json"

    mutate_result = run_command(
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
    expect(mutate_result.returncode == 0)
    expect(output.exists())
    expect(report.exists())

    validate_result = run_command(
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
    expect(not (validate_result.returncode not in {0, 1}))
    expect(not ('"similarity_score"' not in validate_result.stdout))

    report_result = run_command(
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
    expect(report_result.returncode == 0)
    expect(not ('"support_matrix"' not in report_result.stdout))
