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
from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.mutations.code_mobility import CodeMobilityPass
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from r2morph.mutations.data_flow_mutation import DataFlowMutationPass
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.mutations.function_outlining import FunctionOutliningPass
from r2morph.mutations.import_obfuscation import ImportTableObfuscationPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from r2morph.mutations.pattern_substitution import PatternSubstitutionPass
from r2morph.mutations.polymorphic_engine import PolymorphicEnginePass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from r2morph.mutations.self_modifying_code import SelfModifyingCodePass
from r2morph.mutations.short_jump_patching import ShortJumpPatchingPass
from r2morph.mutations.stack_strings import StackStringsPass
from r2morph.mutations.string_obfuscation import StringObfuscationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_nop_x86_64"
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
_CORE_COMPOSITION_CASES = (
    ("BlockReordering", "elf_jumpchain_x86_64", BlockReorderingPass, {"max_functions": 10}, "before_nop", _SEED),
    ("CodeVirtualization", "elf_vm_arith_x86_64", CodeVirtualizationPass, {"max_functions": 2}, "before_nop", _SEED),
    (
        "ControlFlowFlattening",
        "elf_cff_flagdead_x86_64",
        ControlFlowFlatteningPass,
        {"max_functions_to_flatten": 2},
        "before_nop",
        _SEED,
    ),
    (
        "DeadCodeInjection",
        "elf_cff_flagdead_x86_64",
        DeadCodeInjectionPass,
        {"max_injections_per_function": 2},
        "before_nop",
        _SEED,
    ),
    (
        "InstructionExpansion",
        "elf_vm_shift_x86_64",
        InstructionExpansionPass,
        {"max_expansions_per_function": 2},
        "before_nop",
        _SEED,
    ),
    (
        "PatternSubstitution",
        "elf_vm_call_x86_64",
        PatternSubstitutionPass,
        {"max_substitutions_per_function": 2},
        "after_nop",
        20260920,
    ),
    (
        "RegisterSubstitution",
        "elf_vm_redzone_x86_64",
        RegisterSubstitutionPass,
        {"max_substitutions_per_function": 2},
        "before_nop",
        _SEED,
    ),
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
    polymorphic_pass = PolymorphicEnginePass(config={"seed": _SEED, "max_iterations": 10})

    with Binary(mutated, writable=True) as binary:
        binary.analyze("aa")
        result = polymorphic_pass.apply(binary)
        binary.save()

    expect(
        result["mutations_applied"] > 0
        and result["mutations_applied"] == result["successful_mutations"]
        and result["failed_mutations"] == 0
        and emulate_exit_code(mutated) == baseline_exit_code,
        f"result={result!r}, baseline_exit_code={baseline_exit_code}, "
        f"mutated_exit_code={emulate_exit_code(mutated)}",
    )


def test_stack_strings_apply_remains_preview_only_without_rewriting_binary(tmp_path: Path) -> None:
    mutated = tmp_path / "elf_nop_stack_strings"
    shutil.copyfile(_FIXTURE, mutated)
    original_bytes = mutated.read_bytes()

    with Binary(mutated, writable=True) as binary:
        binary.analyze("aa")
        result = StackStringsPass(config={"probability": 1.0, "seed": _SEED}).apply(binary)
        binary.save()

    expect(
        result["strings_transformed"] == 0
        and result["transformation_status"] == "preview-only"
        and result["strings_previewed"] >= 0
        and mutated.read_bytes() == original_bytes
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


@pytest.mark.parametrize(
    "case",
    _CORE_COMPOSITION_CASES,
    ids=[name for name, _, _, _, _, _ in _CORE_COMPOSITION_CASES],
)
def test_core_passes_compose_with_nop_and_preserve_exit_code(
    case: tuple[str, str, type, dict[str, int], str, int],
    tmp_path: Path,
) -> None:
    pass_name, fixture_name, pass_type, pass_options, order, seed = case
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / fixture_name
    mutated = tmp_path / f"{fixture_name}_{pass_name}.composed"
    baseline_exit_code = emulate_exit_code(fixture)
    pass_config = {"probability": 1.0, "seed": seed, **pass_options}
    nop = NopInsertionPass(config={"probability": 1.0, "max_nops_per_function": 2, "seed": seed})
    selected = pass_type(config=pass_config)

    with MorphEngine(config={"seed": seed}) as engine:
        engine.load_binary(fixture).analyze()
        if order == "after_nop":
            engine.add_mutation(nop)
            engine.add_mutation(selected)
        else:
            engine.add_mutation(selected)
            engine.add_mutation(nop)
        result = engine.run(EngineRunOptions(validation_mode="structural", seed=seed))
        engine.save(mutated)

    selected_result = result["pass_results"].get(pass_name, {})
    expect(result["passes_run"] == _EXPECTED_COMPOSED_PASSES and result["failed_passes"] == 0, result)
    expect(selected_result.get("status") == "applied", result)
    expect(emulate_exit_code(mutated) == baseline_exit_code, result)
