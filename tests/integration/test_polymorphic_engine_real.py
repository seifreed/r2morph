"""Real-fixture regression coverage for composed mutation reporting."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.core.binary import Binary
from r2morph.core.engine_run import EngineRunOptions
from r2morph.mutations import ConstantUnfoldingPass, InstructionSubstitutionPass, NopInsertionPass
from r2morph.mutations.polymorphic_engine import PolymorphicEnginePass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"
_SEED = 20260913
_EXPECTED_COMPOSED_PASSES = 2


def test_polymorphic_engine_reports_composed_mutations_and_preserves_exit_code(tmp_path: Path) -> None:
    mutated = tmp_path / "elf_vm_arith_polymorphic"
    shutil.copyfile(_FIXTURE, mutated)
    baseline_exit_code = emulate_exit_code(_FIXTURE)

    with Binary(mutated, writable=True) as binary:
        binary.analyze("aa")
        result = PolymorphicEnginePass(config={"seed": _SEED, "max_iterations": 10}).apply(binary)
        binary.save()

    expect(
        result["mutations_applied"] > 0
        and result["mutations_applied"] == result["successful_mutations"]
        and result["failed_mutations"] == 0
        and emulate_exit_code(mutated) == baseline_exit_code
    )


@pytest.mark.parametrize(
    ("fixture_name", "initial_kind", "initial_name", "seed"),
    (
        pytest.param("elf_nop_x86_64", "nop", "NopInsertion", 20260914, id="nop_then_substitution"),
        pytest.param(
            "elf_constant_unfold_x86_64",
            "constant",
            "ConstantUnfolding",
            20260901,
            id="constant_then_substitution",
        ),
    ),
)
def test_composed_real_passes_preserve_exit_code(
    fixture_name: str,
    initial_kind: str,
    initial_name: str,
    seed: int,
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / fixture_name
    mutated = tmp_path / f"{fixture_name}.composed"
    baseline_exit_code = emulate_exit_code(fixture)

    if initial_kind == "nop":
        initial_pass = NopInsertionPass(config={"probability": 1.0, "max_nops_per_function": 2, "seed": seed})
    else:
        initial_pass = ConstantUnfoldingPass(config={"probability": 1.0, "max_unfolds_per_function": 5, "seed": seed})

    with MorphEngine(config={"seed": seed}) as engine:
        engine.load_binary(fixture).analyze()
        engine.add_mutation(initial_pass)
        engine.add_mutation(
            InstructionSubstitutionPass(
                config={
                    "probability": 1.0,
                    "max_substitutions_per_function": 2,
                    "seed": seed,
                }
            )
        )
        result = engine.run(EngineRunOptions(validation_mode="structural", seed=seed))
        engine.save(mutated)

    expect(
        result["passes_run"] == _EXPECTED_COMPOSED_PASSES
        and result["failed_passes"] == 0
        and result["pass_results"][initial_name]["status"] == "applied"
        and result["pass_results"]["InstructionSubstitution"]["status"] == "applied"
        and emulate_exit_code(mutated) == baseline_exit_code
    )
