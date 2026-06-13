"""Verify selected validation modules import without cycles."""

import importlib

import pytest

VALIDATION_MODULES = [
    "r2morph.validation.constraint_cache",
    "r2morph.validation.binary_region_memory",
    "r2morph.validation.binary_region_comparator",
    "r2morph.validation.benchmark",
    "r2morph.validation.state_merging",
    "r2morph.validation.benchmark_reporting",
]


@pytest.mark.parametrize("module_name", VALIDATION_MODULES)
def test_validation_module_imports_cleanly(module_name: str) -> None:
    mod = importlib.import_module(module_name)
    assert mod is not None
