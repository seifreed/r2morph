"""Verify selected mutation modules import without cycles."""

import importlib

import pytest

MUTATION_MODULES = [
    "r2morph.mutations.code_virtualization_vm",
    "r2morph.mutations.code_virtualization_multi_vm",
    "r2morph.mutations.code_virtualization",
    "r2morph.mutations.hardened_cff",
    "r2morph.mutations.hardened_opaque",
    "r2morph.mutations.hardened_models",
    "r2morph.mutations.conflict_models",
    "r2morph.mutations.conflict_semantic",
    "r2morph.mutations.api_hashing_hashes",
    "r2morph.mutations.control_flow_flattening_helpers",
    "r2morph.mutations.full_cff_helpers",
    "r2morph.mutations.stack_strings_helpers",
    "r2morph.mutations.register_substitution_helpers",
    "r2morph.mutations.instruction_substitution_helpers",
    "r2morph.mutations.instruction_substitution_arm64",
    "r2morph.mutations.code_mobility_models",
    "r2morph.mutations.constant_unfolding_helpers",
    "r2morph.mutations.nop_insertion_helpers",
    "r2morph.mutations.dead_code_injection_helpers",
    "r2morph.mutations.instruction_expansion_helpers",
    "r2morph.mutations.block_reordering_helpers",
    "r2morph.mutations.data_flow_mutation_helpers",
    "r2morph.mutations.polymorphic_engine_models",
    "r2morph.mutations.polymorphic_engine_noop",
    "r2morph.mutations.polymorphic_engine_setup",
    "r2morph.mutations.semantic_validation_models",
]


@pytest.mark.parametrize("module_name", MUTATION_MODULES)
def test_mutation_module_imports_cleanly(module_name: str) -> None:
    mod = importlib.import_module(module_name)
    assert mod is not None
