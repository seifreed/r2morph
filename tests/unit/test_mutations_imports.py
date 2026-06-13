"""Verify selected mutation modules import without cycles."""

import importlib

import pytest

MUTATION_MODULES = [
    "r2morph.mutations.code_virtualization_vm",
    "r2morph.mutations.code_virtualization_multi_vm",
    "r2morph.mutations.code_virtualization",
]


@pytest.mark.parametrize("module_name", MUTATION_MODULES)
def test_mutation_module_imports_cleanly(module_name: str) -> None:
    mod = importlib.import_module(module_name)
    assert mod is not None
