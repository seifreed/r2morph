"""
Real integration tests for PatternSubstitutionPass.

Exercises the pattern-pool subsystem wired into the mutation pipeline against a
deterministic ELF x86_64 fixture. No mocks: a real binary is compiled, mutated,
and validated end-to-end.
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
from r2morph.mutations.pattern_integration import PatternMatchIntegration
from r2morph.mutations.pattern_substitution import PatternSubstitutionPass


def test_enumerate_substitutions_reports_per_match_edits_without_mutating():
    instructions = [
        {"addr": 0x1000, "mnemonic": "mov", "disasm": "mov eax, 0", "size": 5},
        {"addr": 0x1005, "mnemonic": "xor", "disasm": "xor ebx, ebx", "size": 2},
    ]
    integration = PatternMatchIntegration()

    edits = integration.enumerate_substitutions(instructions)

    expect(edits, "expected at least one pattern match on the sample instructions")
    expect(all(set(e) == {"pool", "index", "length", "replacement"} for e in edits))
    expect(all(0 <= e["index"] < len(instructions) for e in edits))
    # The input list must be untouched (enumerate is non-mutating).
    expect(instructions[0]["disasm"] == "mov eax, 0")


def test_pattern_substitution_produces_valid_size_reducing_mutations(
    deterministic_pattern_subst_elf,
):
    with MorphEngine(config={"seed": 1337}) as engine:
        engine.load_binary(deterministic_pattern_subst_elf).analyze()
        engine.add_mutation(PatternSubstitutionPass(config={"probability": 1.0, "max_substitutions_per_function": 20}))
        result = engine.run(EngineRunOptions(validation_mode="structural", seed=1337))
        report = engine.build_report(result)

    expect(not (result["total_mutations"] <= 0))
    expect(report["discarded_mutations"] == [])
    expect(all(m[MUTATION_NAME_KEY] == "PatternSubstitution" for m in report["mutations"]))
    expect(all(m["metadata"]["validation_passed"] is True for m in report["mutations"]))
    expect(report["pass_support"]["PatternSubstitution"]["stability"] == "experimental")


def test_pattern_substitution_preserves_instruction_region_size(
    deterministic_pattern_subst_elf,
):
    with MorphEngine(config={"seed": 7}) as engine:
        engine.load_binary(deterministic_pattern_subst_elf).analyze()
        engine.add_mutation(PatternSubstitutionPass(config={"probability": 1.0}))
        result = engine.run(EngineRunOptions(validation_mode="structural", seed=7))
        report = engine.build_report(result)

    # Every mutation rewrites a region in place: the mutated byte span must equal
    # the original span (NOP-padded), never grow or shrink the binary.
    for mutation in report["mutations"]:
        span = mutation["end_address"] - mutation["start_address"] + 1
        expect(len(mutation["original_bytes"]) == span)
        expect(len(mutation["mutated_bytes"]) == span)
