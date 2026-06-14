"""Verify selected validation modules import without cycles."""

import importlib

import pytest

VALIDATION_MODULES = [
    "r2morph.validation.constraint_cache",
    "r2morph.validation.binary_region_memory",
    "r2morph.validation.binary_region_bridges",
    "r2morph.validation.binary_region_comparator",
    "r2morph.validation.differ_models",
    "r2morph.validation.benchmark",
    "r2morph.validation.benchmark_reporting_exports",
    "r2morph.validation.benchmark_reporting_summary",
    "r2morph.validation.benchmark_reporting_text",
    "r2morph.validation.benchmark_runners",
    "r2morph.validation.benchmark_metrics",
    "r2morph.validation.benchmark_samples",
    "r2morph.validation.leak_detection_models",
    "r2morph.validation.resource_leak_detection",
    "r2morph.validation.performance_regression_models",
    "r2morph.validation.mutation_fuzzer_types",
    "r2morph.validation.mutation_fuzzer_inputs",
    "r2morph.validation.semantic_symbolic",
    "r2morph.validation.semantic_models",
    "r2morph.validation.symbolic_precheck_flow",
    "r2morph.validation.shellcode_equivalence_common",
    "r2morph.validation.shellcode_observables",
    "r2morph.validation.shellcode_transition",
    "r2morph.validation.mutation_annotator_binary",
    "r2morph.validation.mutation_annotator_instruction",
    "r2morph.validation.symbolic_scope_policy",
    "r2morph.validation.validator_runtime",
    "r2morph.validation.state_merging",
    "r2morph.validation.benchmark_reporting",
]


@pytest.mark.parametrize("module_name", VALIDATION_MODULES)
def test_validation_module_imports_cleanly(module_name: str) -> None:
    mod = importlib.import_module(module_name)
    assert mod is not None
