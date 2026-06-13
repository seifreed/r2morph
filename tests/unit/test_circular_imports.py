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
    "r2morph.reporting.report_flow_executor",
    "r2morph.reporting.report_flow_rendering",
    "r2morph.reporting.report_renderer",
    "r2morph.reporting.report_renderer_tables",
    "r2morph.reporting.report_renderer_orchestrator",
    "r2morph.reporting._public_api",
    "r2morph.reporting.report_rendering_primitives",
    "r2morph.reporting.cli_commands",
    "r2morph.reporting.report_context_resolver",
    "r2morph.reporting.report_gate_helpers",
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
    "r2morph.reporting.report_context",
    "r2morph.reporting.report_view_resolution",
    "r2morph.reporting.report_output_policy",
    "r2morph.reporting.summary_aggregator",
    "r2morph.reporting.summary_aggregator_symbolic",
    "r2morph.reporting.summary_aggregator_evidence",
    "r2morph.reporting.summary_aggregator_summary",
    "r2morph.reporting.sarif_result_builder",
    "r2morph.factories",
    "r2morph.cli_workflows",
    "r2morph.core.report_helpers_evidence",
    "r2morph.core.report_helpers_projection",
    "r2morph.core.report_helpers_validation",
    "r2morph.core.report_helpers_adjustment",
    "r2morph.core.report_helpers_risk",
    "r2morph.core.report_helpers_triage",
    "r2morph.analysis.pointer_analysis",
    "r2morph.analysis.type_inference_types",
    "r2morph.analysis.type_inference_interprocedural",
    "r2morph.analysis.type_inference_core",
    "r2morph.analysis.type_inference_arm",
    "r2morph.analysis.type_inference_queries",
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
