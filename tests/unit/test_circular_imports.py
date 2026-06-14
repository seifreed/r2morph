"""Verify no circular imports in reporting/ and core/ packages."""

import importlib
import sys

import pytest

REPORTING_MODULES = [
    "r2morph.reporting",
    "r2morph.reporting.gate_evaluator",
    "r2morph.reporting.report_helpers",
    "r2morph.reporting.report_helpers_classification",
    "r2morph.reporting.report_rendering",
    "r2morph.reporting.report_rendering_sections",
    "r2morph.reporting.report_rendering_flow_sections",
    "r2morph.reporting.report_rendering_pass_sections",
    "r2morph.reporting.report_rendering_tables",
    "r2morph.reporting.report_rendering_pass_tables",
    "r2morph.reporting.report_rendering_flow_text_sections",
    "r2morph.reporting.report_rendering_symbolic_tables",
    "r2morph.reporting.report_rendering_text_sections",
    "r2morph.reporting.report_rendering_summary_tables",
    "r2morph.reporting.report_pass_list_resolution",
    "r2morph.reporting.report_flow_executor",
    "r2morph.reporting.report_flow_rendering",
    "r2morph.reporting.report_renderer",
    "r2morph.reporting.report_renderer_tables",
    "r2morph.reporting.report_renderer_orchestrator",
    "r2morph.reporting.sarif_schema_core",
    "r2morph.reporting.sarif_formatter_builders",
    "r2morph.reporting._public_api",
    "r2morph.reporting.report_rendering_primitives",
    "r2morph.reporting.cli_commands",
    "r2morph.reporting.report_context_resolver",
    "r2morph.reporting.report_context_gate_state",
    "r2morph.reporting.report_context_compat",
    "r2morph.reporting.report_context_mapping",
    "r2morph.reporting.report_filter_messages",
    "r2morph.reporting.report_command_io",
    "r2morph.reporting.report_mismatch_state",
    "r2morph.reporting.report_pass_filters",
    "r2morph.reporting.report_gate_filters",
    "r2morph.reporting.report_gate_helpers",
    "r2morph.reporting.report_emitter",
    "r2morph.reporting.report_assembler",
    "r2morph.reporting.report_assembler_artifacts",
    "r2morph.reporting.report_resolver",
    "r2morph.reporting.report_orchestrator",
    "r2morph.reporting.filtered_summary_builder",
    "r2morph.reporting.filtered_summary_payloads",
    "r2morph.reporting.filtered_summary_mismatch_payloads",
    "r2morph.reporting.filtered_summary_population",
    "r2morph.reporting.filtered_summary_discarded",
    "r2morph.reporting.filtered_summary_pass_details",
    "r2morph.reporting.filtered_summary_gate",
    "r2morph.reporting.filtered_summary_risk_coverage",
    "r2morph.reporting.filtered_summary_risk",
    "r2morph.reporting.filtered_summary_degradation",
    "r2morph.reporting.filtered_summary_triage",
    "r2morph.reporting.filtered_summary_sections",
    "r2morph.reporting.filtered_summary_symbolic",
    "r2morph.reporting.report_view_builder",
    "r2morph.reporting.report_view_sections",
    "r2morph.reporting.report_view_summary",
    "r2morph.reporting.report_view_details",
    "r2morph.reporting.report_view_gate_views",
    "r2morph.reporting.report_view_pass_views",
    "r2morph.reporting.report_view_mismatch_detail",
    "r2morph.reporting.report_view_mismatch_views",
    "r2morph.reporting.report_view_validation_detail",
    "r2morph.reporting.report_view_gate_detail",
    "r2morph.reporting.report_view_summary_payload",
    "r2morph.reporting.report_context",
    "r2morph.reporting.report_view_resolution",
    "r2morph.reporting.report_pass_resolution",
    "r2morph.reporting.report_output_policy",
    "r2morph.reporting.report_builder_models",
    "r2morph.reporting.summary_aggregator",
    "r2morph.reporting.summary_aggregator_symbolic",
    "r2morph.reporting.summary_aggregator_evidence",
    "r2morph.reporting.summary_aggregator_summary",
    "r2morph.reporting.sarif_result_builder",
    "r2morph.reporting.sarif_schema_core",
    "r2morph.factories",
    "r2morph.cli_workflows",
    "r2morph.core.engine_lifecycle",
    "r2morph.core.engine_run",
    "r2morph.core.engine_output",
    "r2morph.core.engine_wiring",
    "r2morph.core.engine_mutations",
    "r2morph.core.parallel_planner",
    "r2morph.core.parallel_executor_models",
    "r2morph.core.parallel_executor_task_helpers",
    "r2morph.core.parallel_execution_summary",
    "r2morph.core.parallel_pass_execution",
    "r2morph.core.parallel_rollback",
    "r2morph.core.parallel_work_queue",
    "r2morph.core.parallel_result_merger",
    "r2morph.core.parallel_checkpointing",
    "r2morph.core.binary_file_lock",
    "r2morph.core.analysis_cache_models",
    "r2morph.core.analysis_cache_storage",
    "r2morph.core.analysis_cache_keys",
    "r2morph.core.analysis_cache_entries",
    "r2morph.core.analysis_cache_cleanup",
    "r2morph.core.binary_lifecycle",
    "r2morph.core.report_helpers_evidence",
    "r2morph.core.report_helpers_projection",
    "r2morph.core.report_helpers_validation",
    "r2morph.core.report_helpers_adjustment",
    "r2morph.core.report_helpers_risk",
    "r2morph.core.report_helpers_triage",
    "r2morph.analysis.pointer_analysis",
    "r2morph.analysis.call_graph_cache",
    "r2morph.analysis.call_graph_models",
    "r2morph.analysis.pattern_preservation_models",
    "r2morph.analysis.pattern_preservation_detection",
    "r2morph.analysis.switch_table_models",
    "r2morph.analysis.critical_nodes_models",
    "r2morph.analysis.switch_table_patterns",
    "r2morph.analysis.memory_flow_helpers",
    "r2morph.analysis.memory_flow_models",
    "r2morph.analysis.symbolic.constraint_solver_parsing",
    "r2morph.analysis.symbolic.syntia_models",
    "r2morph.analysis.symbolic.syntia_equivalence_helpers",
    "r2morph.analysis.symbolic.syntia_analysis_helpers",
    "r2morph.analysis.critical_nodes_scorer",
    "r2morph.validation.cfg_integrity_models",
    "r2morph.validation.integrity_repair_helpers",
    "r2morph.platform.pe_handler_parsing",
    "r2morph.platform.pe_handler_repair",
    "r2morph.platform.macho_handler_repair",
    "r2morph.devirtualization.binary_rewriter_models",
    "r2morph.devirtualization.cfo_simplifier_detection",
    "r2morph.devirtualization.cfo_simplifier_models",
    "r2morph.devirtualization.cfo_simplifier_transforms",
    "r2morph.devirtualization.iterative_simplifier_models",
    "r2morph.devirtualization.vm_handler_models",
    "r2morph.devirtualization.vm_handler_metrics",
    "r2morph.devirtualization.vm_handler_patterns",
    "r2morph.devirtualization.mba_solver_helpers",
    "r2morph.devirtualization.iterative_simplifier_passes",
    "r2morph.detection.anti_analysis_bypass_models",
    "r2morph.detection.anti_analysis_bypass_methods",
    "r2morph.detection.anti_analysis_detection",
    "r2morph.detection.evasion_scorer_helpers",
    "r2morph.detection.control_flow_detector_models",
    "r2morph.detection.entropy_analyzer_models",
    "r2morph.detection.evasion_scorer_models",
    "r2morph.detection.packer_signature_models",
    "r2morph.detection.packer_signature_analysis",
    "r2morph.detection.obfuscation_detector_models",
    "r2morph.detection.pattern_matcher_models",
    "r2morph.validation.differ_helpers",
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
    "r2morph.validation.fuzzer_inputs",
    "r2morph.validation.fuzzer_models",
    "r2morph.validation.benchmark_reporting_exports",
    "r2morph.validation.benchmark_reporting_summary",
    "r2morph.validation.benchmark_reporting_text",
    "r2morph.validation.benchmark_suite",
    "r2morph.validation.validator_execution",
    "r2morph.validation.cfg_integrity_helpers",
    "r2morph.validation.leak_detection_models",
    "r2morph.validation.object_tracker",
    "r2morph.validation.resource_leak_detection",
    "r2morph.validation.performance_regression_models",
    "r2morph.validation.mutation_fuzzer_inputs",
    "r2morph.validation.mutation_fuzzer_types",
    "r2morph.validation.semantic_invariant_models",
    "r2morph.validation.constraint_cache_models",
    "r2morph.analysis.type_inference_types",
    "r2morph.analysis.type_inference_interprocedural",
    "r2morph.analysis.type_inference_core",
    "r2morph.analysis.type_inference_arm",
    "r2morph.analysis.type_inference_queries",
    "r2morph.analysis.cfg_models",
    "r2morph.analysis.cfg_builder_helpers",
    "r2morph.analysis.cfg_exception_helpers",
    "r2morph.platform.elf_handler_parsing",
    "r2morph.platform.elf_handler_metadata",
    "r2morph.platform.elf_handler_symbols",
    "r2morph.platform.elf_handler_symbol_preservation",
    "r2morph.platform.elf_handler_code_caves",
    "r2morph.platform.elf_handler_section_mutation",
    "r2morph.platform.elf_handler_tables",
    "r2morph.reporting.sarif_rule_ids",
    "r2morph.validation.benchmark_reporting_sections",
    "r2morph.platform.pe_handler_projection",
    "r2morph.analysis.symbolic.constraint_solver_models",
    "r2morph.analysis.symbolic.state_manager_models",
    "r2morph.platform.elf_handler_validation",
    "r2morph.tui_diff_helpers",
]


@pytest.mark.parametrize("module_name", REPORTING_MODULES)
def test_reporting_module_imports_cleanly(module_name):
    mod = importlib.import_module(module_name)
    assert mod is not None


def test_package_root_defers_heavy_exports():
    module = importlib.import_module("r2morph")

    module.__dict__.pop("Binary", None)
    module.__dict__.pop("MorphEngine", None)
    module.__dict__.pop("Pipeline", None)
    sys.modules.pop("r2morph.core.binary", None)
    sys.modules.pop("r2morph.core.engine", None)
    sys.modules.pop("r2morph.pipeline.pipeline", None)

    assert "r2morph.core.binary" not in sys.modules
    assert "r2morph.core.engine" not in sys.modules
    assert "r2morph.pipeline.pipeline" not in sys.modules

    assert module.Binary.__name__ == "Binary"
    assert module.MorphEngine.__name__ == "MorphEngine"
    assert module.Pipeline.__name__ == "Pipeline"

    assert "r2morph.core.binary" in sys.modules
    assert "r2morph.core.engine" in sys.modules
    assert "r2morph.pipeline.pipeline" in sys.modules


def test_reporting_package_defers_heavy_exports():
    module = importlib.import_module("r2morph.reporting")

    module.__dict__.pop("ReportBuilder", None)
    module.__dict__.pop("SARIFFormatter", None)
    sys.modules.pop("r2morph.reporting.report_builder", None)
    sys.modules.pop("r2morph.reporting.sarif_formatter", None)

    assert "r2morph.reporting.report_builder" not in sys.modules
    assert "r2morph.reporting.sarif_formatter" not in sys.modules

    assert module.ReportBuilder.__name__ == "ReportBuilder"
    assert module.SARIFFormatter.__name__ == "SARIFFormatter"

    assert "r2morph.reporting.report_builder" in sys.modules
    assert "r2morph.reporting.sarif_formatter" in sys.modules


def test_report_builder_only_keeps_payload_construction_helpers():
    from r2morph.reporting.report_builder import ReportBuilder

    assert not hasattr(ReportBuilder, "resolve_report_context")
    assert not hasattr(ReportBuilder, "resolve_min_severity")
    assert not hasattr(ReportBuilder, "resolve_report_pass_filter")
