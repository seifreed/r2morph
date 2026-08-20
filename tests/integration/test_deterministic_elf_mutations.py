"""
Real integration tests against deterministic ELF x86_64 fixtures.
"""

import importlib.util

import pytest

from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)

from r2morph import MorphEngine
from r2morph.core.engine_run import EngineRunOptions
from r2morph.mutations import (
    InstructionSubstitutionPass,
    NopInsertionPass,
    RegisterSubstitutionPass,
)

_EXPECTED_LEN_MUTATION_METADATA_GET_SYMBOLIC_BINARY_MUT_2 = 2
_EXPECTED_LEN_MUTATION_METADATA_GET_SYMBOLIC_BINARY_ORI_2 = 2
_EXPECTED_MUTATION_METADATA_GET_SYMBOLIC_BINARY_REGION__2 = 2
_EXPECTED_MUTATION_METADATA_GET_SYMBOLIC_BINARY_STEP_BU_2 = 2
_EXPECTED_MUTATION_METADATA_GET_SYMBOLIC_BINARY_STEP_BU_2_2 = 2


def test_deterministic_nop_fixture_produces_real_mutations(deterministic_nop_elf):
    with MorphEngine(config={"seed": 1337}) as engine:
        engine.load_binary(deterministic_nop_elf).analyze()
        engine.add_mutation(
            NopInsertionPass(
                config={
                    "probability": 1.0,
                    "max_nops_per_function": 8,
                    "use_creative_nops": False,
                    "seed": 1337,
                }
            )
        )
        result = engine.run(EngineRunOptions(validation_mode="structural", seed=1337))
        report = engine.build_report(result)

    expect(not (result["total_mutations"] <= 0))
    expect(report["discarded_mutations"] == [])
    expect(report["pass_support"]["NopInsertion"]["stability"] == "stable")
    expect(all(mutation[MUTATION_NAME_KEY] == "NopInsertion" for mutation in report["mutations"]))
    expect(all(mutation["byte_diff_count"] > 0 for mutation in report["mutations"]))
    expect(all(mutation["metadata"]["validation_passed"] is True for mutation in report["mutations"]))


def test_deterministic_nop_fixture_gets_real_binary_symbolic_coverage(
    deterministic_nop_elf,
):
    with MorphEngine(config={"seed": 1337}) as engine:
        engine.load_binary(deterministic_nop_elf).analyze()
        engine.add_mutation(
            NopInsertionPass(
                config={
                    "probability": 1.0,
                    "max_nops_per_function": 8,
                    "use_creative_nops": False,
                    "seed": 1337,
                }
            )
        )
        result = engine.run(EngineRunOptions(validation_mode="symbolic", seed=1337))
        report = engine.build_report(result)

    expect(not (result["total_mutations"] <= 0))
    expect(not (report["validation"]["symbolic"]["requested"] is not True))
    expect(report["validation"]["symbolic"]["statuses"])
    expect(report["validation"]["symbolic"]["statuses"][0]["status"] == "real-binary-observables-match")
    expect(
        all(
            mutation["metadata"].get("symbolic_binary_check_performed") is True
            and mutation["metadata"].get("symbolic_binary_step_budget", 0)
            >= _EXPECTED_MUTATION_METADATA_GET_SYMBOLIC_BINARY_STEP_BU_2
            and mutation["metadata"].get("symbolic_binary_region_exit_budget", 0)
            >= _EXPECTED_MUTATION_METADATA_GET_SYMBOLIC_BINARY_REGION__2
            and mutation["metadata"].get("symbolic_binary_step_strategy")
            in {
                "region-exit",
                "region-exit-fallback-budget",
            }
            for mutation in report["mutations"]
        )
    )
    expect(all(not mutation["metadata"].get("symbolic_binary_mismatches", []) for mutation in report["mutations"]))
    expect(
        all(
            mutation["metadata"].get("symbolic_binary_original_region_exit_address")
            == mutation["metadata"].get("symbolic_binary_mutated_region_exit_address")
            and mutation["metadata"].get("symbolic_binary_original_region_exit_steps", 0) >= 1
            and mutation["metadata"].get("symbolic_binary_mutated_region_exit_steps", 0)
            >= mutation["metadata"].get("symbolic_binary_original_region_exit_steps", 0)
            and len(mutation["metadata"].get("symbolic_binary_original_trace_addresses", []))
            >= _EXPECTED_LEN_MUTATION_METADATA_GET_SYMBOLIC_BINARY_ORI_2
            and len(mutation["metadata"].get("symbolic_binary_mutated_trace_addresses", []))
            >= _EXPECTED_LEN_MUTATION_METADATA_GET_SYMBOLIC_BINARY_MUT_2
            and mutation["metadata"].get("symbolic_binary_control_flow_observables")
            == [
                "region_exit_address",
                "region_exit_steps",
            ]
            and mutation["metadata"].get("symbolic_binary_original_memory_write_count", -1) >= 0
            and mutation["metadata"].get("symbolic_binary_mutated_memory_write_count", -1) >= 0
            for mutation in report["mutations"]
        )
    )
    evidence = report["passes"]["NopInsertion"]["evidence_summary"]
    expect(not (evidence["symbolic_binary_regions_checked"] < 1))
    expect(evidence["symbolic_binary_mismatched_regions"] == 0)
    expect(evidence["control_flow_observables"] == ["region_exit_address", "region_exit_steps"])
    expect(not (evidence["max_mutated_trace_length"] < evidence["max_original_trace_length"]))


def test_deterministic_instruction_substitution_fixture_gets_symbolic_coverage(
    deterministic_substitute_elf,
):
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
        result = engine.run(EngineRunOptions(validation_mode="symbolic", seed=1337))
        report = engine.build_report(result)

    expect(not (result["total_mutations"] <= 0))
    expect(not (report["validation"]["symbolic"]["requested"] is not True))
    expect(report["validation"]["symbolic"]["statuses"])
    expect(report["validation"]["symbolic"]["supported_passes"] == ["InstructionSubstitution"])
    expect(
        report["pass_support"]["InstructionSubstitution"]["validator_capabilities"]["symbolic"]["confidence"]
        == "best among stable passes"
    )
    expect(
        any(
            mutation["metadata"].get("symbolic_status")
            in {
                "bounded-step-known-equivalence",
                "bounded-step-observables-match",
                "bounded-step-observable-mismatch",
                "bounded-step-passed",
                "shellcode-observables-match",
                "shellcode-observable-mismatch",
                "real-binary-observables-match",
                "real-binary-observable-mismatch",
            }
            for mutation in report["mutations"]
        )
    )
    expect(
        any(
            mutation["metadata"].get("symbolic_binary_check_performed") is True
            and mutation["metadata"].get("symbolic_binary_step_budget", 0) >= 1
            and mutation["metadata"].get("symbolic_binary_step_strategy")
            in {
                "region-exit",
                "region-exit-fallback-budget",
            }
            for mutation in report["mutations"]
        )
    )
    expect(not (report["summary"]["changed_bytes"] <= 0))


def test_deterministic_register_fixture_produces_real_substitutions(deterministic_register_elf):
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
        result = engine.run(EngineRunOptions(validation_mode="structural", seed=1337))
        report = engine.build_report(result)

    expect(not (result["total_mutations"] <= 0))
    expect(report["pass_support"]["RegisterSubstitution"]["stability"] == "stable")
    expect(
        all(
            mutation["recorded_after_seconds"] is None or mutation["recorded_after_seconds"] >= 0.0
            for mutation in report["mutations"]
        )
    )


def test_deterministic_register_fixture_reports_real_binary_symbolic_mismatch(
    deterministic_register_elf,
):
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
        result = engine.run(EngineRunOptions(validation_mode="symbolic", seed=1337))
        report = engine.build_report(result)

    expect(not (result["total_mutations"] <= 0))
    expect(not (report["validation"]["symbolic"]["requested"] is not True))
    expect(not ("RegisterSubstitution" not in report["validation"]["symbolic"]["fallback_passes"]))
    expect(report["validation"]["symbolic"]["statuses"][0]["status"] == "real-binary-observable-mismatch")
    expect(
        not (
            report["pass_support"]["RegisterSubstitution"]["validator_capabilities"]["runtime"]["recommended"]
            is not True
        )
    )
    expect(
        not (
            report["pass_support"]["RegisterSubstitution"]["validator_capabilities"]["symbolic"]["recommended"]
            is not False
        )
    )
    expect(
        all(
            mutation["metadata"].get("symbolic_status") == "real-binary-observable-mismatch"
            for mutation in report["mutations"]
        )
    )
    expect(
        all(
            mutation["metadata"].get("symbolic_binary_check_performed") is True
            and mutation["metadata"].get("symbolic_binary_step_budget", 0)
            >= _EXPECTED_MUTATION_METADATA_GET_SYMBOLIC_BINARY_STEP_BU_2_2
            and mutation["metadata"].get("symbolic_binary_step_strategy")
            in {
                "region-exit",
                "region-exit-fallback-budget",
            }
            for mutation in report["mutations"]
        )
    )
    expect(
        all(
            mutation["metadata"].get("symbolic_binary_control_flow_observables")
            == [
                "region_exit_address",
                "region_exit_steps",
            ]
            and isinstance(mutation["metadata"].get("symbolic_binary_original_trace_addresses"), list)
            and isinstance(mutation["metadata"].get("symbolic_binary_mutated_trace_addresses"), list)
            for mutation in report["mutations"]
        )
    )
    evidence = report["passes"]["RegisterSubstitution"]["evidence_summary"]
    expect(not (evidence["symbolic_binary_regions_checked"] < 1))
    expect(not (evidence["symbolic_binary_mismatched_regions"] < 1))
    expect(evidence["symbolic_regions"][0]["mismatches"])


def test_deterministic_fail_fixture_stays_clean(deterministic_fail_elf):
    with MorphEngine(config={"seed": 1337}) as engine:
        engine.load_binary(deterministic_fail_elf).analyze()
        engine.add_mutation(NopInsertionPass(config={"probability": 1.0, "seed": 1337}))
        result = engine.run(EngineRunOptions(validation_mode="structural", seed=1337))
        report = engine.build_report(result)

    expect(result["total_mutations"] == 0)
    expect(report["mutations"] == [])
    expect(report["discarded_mutations"] == [])
    expect(not (report["validation"]["all_passed"] is not True))
