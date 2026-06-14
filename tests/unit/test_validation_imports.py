"""Verify selected validation modules import without cycles."""

import importlib

import pytest

VALIDATION_MODULES = [
    "r2morph.validation.constraint_cache",
    "r2morph.validation.binary_region_memory",
    "r2morph.validation.binary_region_bridges",
    "r2morph.validation.binary_region_comparator",
    "r2morph.validation.differ_models",
    "r2morph.analysis.invariant_models",
    "r2morph.validation.manager_models",
    "r2morph.validation.semantic_report_models",
    "r2morph.validation.semantic_invariant_helpers",
    "r2morph.validation.benchmark",
    "r2morph.validation.benchmark_reporting_exports",
    "r2morph.validation.benchmark_reporting_overview",
    "r2morph.validation.benchmark_reporting_breakdown_sections",
    "r2morph.validation.benchmark_reporting_summary",
    "r2morph.validation.benchmark_reporting_text",
    "r2morph.validation.benchmark_suite",
    "r2morph.validation.benchmark_runners",
    "r2morph.validation.benchmark_metrics",
    "r2morph.validation.benchmark_samples",
    "r2morph.validation.performance_regression_storage",
    "r2morph.validation.performance_regression_metadata",
    "r2morph.validation.performance_regression_measurement",
    "r2morph.validation.performance_regression_suite",
    "r2morph.validation.performance_regression_comparison",
    "r2morph.validation.regression_models",
    "r2morph.validation.regression_comparison",
    "r2morph.validation.regression_storage",
    "r2morph.validation.regression_baselines",
    "r2morph.validation.leak_detection_models",
    "r2morph.validation.object_tracker",
    "r2morph.validation.fuzzer_inputs",
    "r2morph.validation.fuzzer_models",
    "r2morph.validation.resource_leak_detection",
    "r2morph.validation.performance_regression_models",
    "r2morph.validation.mutation_fuzzer_types",
    "r2morph.validation.mutation_fuzzer_inputs",
    "r2morph.validation.mutation_fuzzer_continuous",
    "r2morph.validation.semantic_invariant_models",
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
    "r2morph.validation.validator_execution",
    "r2morph.validation.validator_results",
    "r2morph.validation.cfg_integrity_helpers",
    "r2morph.validation.state_merging",
    "r2morph.validation.benchmark_reporting",
]


@pytest.mark.parametrize("module_name", VALIDATION_MODULES)
def test_validation_module_imports_cleanly(module_name: str) -> None:
    mod = importlib.import_module(module_name)
    assert mod is not None
