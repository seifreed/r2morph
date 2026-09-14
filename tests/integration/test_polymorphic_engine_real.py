"""Real-fixture regression coverage for composed mutation reporting."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.core.binary import Binary
from r2morph.core.engine_run import EngineRunOptions
from r2morph.mutations import ConstantUnfoldingPass, InstructionSubstitutionPass, NopInsertionPass
from r2morph.mutations.anti_disassembly import AntiDisassemblyPass
from r2morph.mutations.api_hashing import APIHashingPass
from r2morph.mutations.code_mobility import CodeMobilityPass
from r2morph.mutations.data_flow_mutation import DataFlowMutationPass
from r2morph.mutations.function_outlining import FunctionOutliningPass
from r2morph.mutations.import_obfuscation import ImportTableObfuscationPass
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from r2morph.mutations.polymorphic_engine import PolymorphicEnginePass
from r2morph.mutations.self_modifying_code import SelfModifyingCodePass
from r2morph.mutations.short_jump_patching import ShortJumpPatchingPass
from r2morph.mutations.stack_strings import StackStringsPass
from r2morph.mutations.string_obfuscation import StringObfuscationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"
_SEED = 20260913
_EXPECTED_COMPOSED_PASSES = 2
_EXTENDED_COMPOSITION_PASSES = (
    ("AntiDisassembly", AntiDisassemblyPass),
    ("APIHashing", APIHashingPass),
    ("CodeMobility", CodeMobilityPass),
    ("DataFlowMutation", DataFlowMutationPass),
    ("FunctionOutlining", FunctionOutliningPass),
    ("ImportObfuscation", ImportTableObfuscationPass),
    ("OpaquePredicates", OpaquePredicatePass),
    ("PolymorphicEngine", PolymorphicEnginePass),
    ("SelfModifyingCode", SelfModifyingCodePass),
    ("ShortJumpPatching", ShortJumpPatchingPass),
    ("StackStrings", StackStringsPass),
    ("StringObfuscation", StringObfuscationPass),
)


def _build_composition_pass(name: str, seed: int):
    if name == "nop":
        return NopInsertionPass(config={"probability": 1.0, "max_nops_per_function": 2, "seed": seed})
    if name == "constant":
        return ConstantUnfoldingPass(config={"probability": 1.0, "max_unfolds_per_function": 5, "seed": seed})
    if name == "substitution":
        return InstructionSubstitutionPass(
            config={"probability": 1.0, "max_substitutions_per_function": 2, "seed": seed}
        )
    raise ValueError(f"unsupported composition pass: {name}")


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
    "case",
    (
        pytest.param(
            ("elf_nop_x86_64", "nop", "NopInsertion", "substitution", "InstructionSubstitution", 20260914),
            id="nop_then_substitution",
        ),
        pytest.param(
            (
                "elf_constant_unfold_x86_64",
                "constant",
                "ConstantUnfolding",
                "substitution",
                "InstructionSubstitution",
                20260901,
            ),
            id="constant_then_substitution",
        ),
        pytest.param(
            ("elf_nop_x86_64", "nop", "NopInsertion", "constant", "ConstantUnfolding", 20260915),
            id="nop_then_constant",
        ),
        pytest.param(
            ("elf_constant_unfold_x86_64", "constant", "ConstantUnfolding", "nop", "NopInsertion", 20260916),
            id="constant_then_nop",
        ),
        pytest.param(
            ("elf_vm_arith_x86_64", "substitution", "InstructionSubstitution", "nop", "NopInsertion", 20260917),
            id="substitution_then_nop",
        ),
        pytest.param(
            (
                "elf_vm_arith_x86_64",
                "substitution",
                "InstructionSubstitution",
                "constant",
                "ConstantUnfolding",
                20260918,
            ),
            id="substitution_then_constant",
        ),
    ),
)
def test_composed_real_passes_preserve_exit_code(
    case: tuple[str, str, str, str, str, int],
    tmp_path: Path,
) -> None:
    fixture_name, first_kind, first_name, second_kind, second_name, seed = case
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / fixture_name
    mutated = tmp_path / f"{fixture_name}.composed"
    baseline_exit_code = emulate_exit_code(fixture)

    with MorphEngine(config={"seed": seed}) as engine:
        engine.load_binary(fixture).analyze()
        engine.add_mutation(_build_composition_pass(first_kind, seed))
        engine.add_mutation(_build_composition_pass(second_kind, seed))
        result = engine.run(EngineRunOptions(validation_mode="structural", seed=seed))
        engine.save(mutated)

    first_result = result["pass_results"].get(first_name, {})
    second_result = result["pass_results"].get(second_name, {})
    expect(result["passes_run"] == _EXPECTED_COMPOSED_PASSES and result["failed_passes"] == 0, result)
    expect(first_result.get("status") == "applied", result)
    if "status" in second_result:
        expect(second_result["status"] == "applied", result)
    else:
        expect(second_result.get("mutations_applied") == 0, result)
    expect(emulate_exit_code(mutated) == baseline_exit_code, result)


@pytest.mark.parametrize(
    "pass_name,pass_type",
    _EXTENDED_COMPOSITION_PASSES,
    ids=[name for name, _ in _EXTENDED_COMPOSITION_PASSES],
)
def test_extended_passes_compose_after_nop_without_corrupting_fixture(
    pass_name: str,
    pass_type: type,
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_nop_x86_64"
    mutated = tmp_path / f"elf_nop_{pass_name}.composed"
    baseline_exit_code = emulate_exit_code(fixture)

    with MorphEngine(config={"seed": _SEED}) as engine:
        engine.load_binary(fixture).analyze()
        engine.add_mutation(NopInsertionPass(config={"probability": 1.0, "max_nops_per_function": 2, "seed": _SEED}))
        engine.add_mutation(pass_type(config={"probability": 1.0, "seed": _SEED}))
        result = engine.run(EngineRunOptions(validation_mode="structural", seed=_SEED))
        engine.save(mutated)

    expect(result["passes_run"] == _EXPECTED_COMPOSED_PASSES and result["failed_passes"] == 0, result)
    expect(emulate_exit_code(mutated) == baseline_exit_code, result)


@pytest.mark.parametrize(
    "pass_name,pass_type",
    _EXTENDED_COMPOSITION_PASSES,
    ids=[name for name, _ in _EXTENDED_COMPOSITION_PASSES],
)
def test_extended_passes_compose_before_nop_without_corrupting_fixture(
    pass_name: str,
    pass_type: type,
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_nop_x86_64"
    mutated = tmp_path / f"elf_{pass_name}_then_nop.composed"
    baseline_exit_code = emulate_exit_code(fixture)

    with MorphEngine(config={"seed": _SEED}) as engine:
        engine.load_binary(fixture).analyze()
        engine.add_mutation(pass_type(config={"probability": 1.0, "seed": _SEED}))
        engine.add_mutation(NopInsertionPass(config={"probability": 1.0, "max_nops_per_function": 2, "seed": _SEED}))
        result = engine.run(EngineRunOptions(validation_mode="structural", seed=_SEED))
        engine.save(mutated)

    expect(result["passes_run"] == _EXPECTED_COMPOSED_PASSES and result["failed_passes"] == 0, result)
    expect(emulate_exit_code(mutated) == baseline_exit_code, result)
