"""
Reporting subpackage for report building, filtering, and rendering.

The package root stays thin and resolves symbols lazily so importing
``r2morph.reporting`` does not eagerly pull the whole reporting graph
into memory.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_LAZY_RENDERING_NAMES = {
    "CONSOLE",
    "create_table",
    "render_pass_capabilities",
    "render_pass_validation_contexts",
    "render_symbolic_sections",
    "render_gate_sections",
    "render_degradation_sections",
    "render_only_mismatches_sections",
    "render_only_pass_sections",
    "render_report_filter_messages",
    "render_summary_table",
    "render_gate_evaluation_sections",
    "render_general_report_sections",
    "render_general_only_pass_sections",
    "render_mismatch_summary_sections",
    "render_validation_context_table",
}

__all__ = [
    # Gate evaluation
    "SEVERITY_ORDER",
    "GateEvaluator",
    "GateFailure",
    # Summary aggregation
    "SummaryAggregator",
    "SymbolicAggregator",
    "EvidenceAggregator",
    # Report filtering
    "ReportFilters",
    "PassFilterResolver",
    # Report building
    "ReportBuilder",
    "ReportContext",
    "FilteredReport",
    # Rendering
    "ReportRenderer",
    "ConsoleRenderer",
    "CONSOLE",
    "create_table",
    "render_pass_capabilities",
    "render_pass_validation_contexts",
    "render_symbolic_sections",
    "render_gate_sections",
    "render_degradation_sections",
    "render_only_mismatches_sections",
    "render_only_pass_sections",
    "render_report_filter_messages",
    "render_summary_table",
    "render_gate_evaluation_sections",
    "render_general_report_sections",
    "render_general_only_pass_sections",
    "render_mismatch_summary_sections",
    "render_validation_context_table",
    # Report state resolution (public API)
    "resolve_general_symbolic_state",
    "resolve_mismatch_view",
    "resolve_pass_filter_sets",
    # Report emission
    "emit_report_payload",
    "enforce_report_requirements",
    "severity_threshold_met",
    "report_view_has_results",
    "gate_failure_result_count",
    # SARIF schema types
    "SARIFReport",
    "SARIFRun",
    "SARIFResult",
    "SARIFRule",
    "SARIFTool",
    "SARIFToolComponent",
    "SARIFArtifact",
    "SARIFArtifactLocation",
    "SARIFLocation",
    "SARIFPhysicalLocation",
    "SARIFRegion",
    "SARIFMessage",
    "SARIFLevel",
    "SARIFFix",
    "SARIFInvocation",
    "SARIFNotification",
    "SARIFSnippet",
    "SARIFLogicalLocation",
    "SARIFFileChange",
    "SARIFReplacement",
    # SARIF formatting
    "SARIFFormatter",
    "MutationResult",
    "ValidationResult",
    "ReportData",
    "format_as_sarif",
]


def __getattr__(name: str) -> Any:
    """Resolve public reporting symbols lazily on first access."""
    lazy_exports: dict[str, tuple[str, str]] = {
        "SEVERITY_ORDER": ("r2morph.reporting.gate_evaluator", "SEVERITY_ORDER"),
        "GateEvaluator": ("r2morph.reporting.gate_evaluator", "GateEvaluator"),
        "GateFailure": ("r2morph.reporting.gate_evaluator", "GateFailure"),
        "FilteredReport": ("r2morph.reporting.report_builder", "FilteredReport"),
        "ReportBuilder": ("r2morph.reporting.report_builder", "ReportBuilder"),
        "ReportContext": ("r2morph.reporting.report_builder", "ReportContext"),
        "emit_report_payload": ("r2morph.reporting.report_emitter", "emit_report_payload"),
        "enforce_report_requirements": ("r2morph.reporting.report_emitter", "enforce_report_requirements"),
        "gate_failure_result_count": ("r2morph.reporting.report_emitter", "gate_failure_result_count"),
        "report_view_has_results": ("r2morph.reporting.report_emitter", "report_view_has_results"),
        "severity_threshold_met": ("r2morph.reporting.report_emitter", "severity_threshold_met"),
        "PassFilterResolver": ("r2morph.reporting.report_filters", "PassFilterResolver"),
        "ReportFilters": ("r2morph.reporting.report_filters", "ReportFilters"),
        "ConsoleRenderer": ("r2morph.reporting.report_renderer", "ConsoleRenderer"),
        "ReportRenderer": ("r2morph.reporting.report_renderer", "ReportRenderer"),
        "_has_structural_risk": ("r2morph.reporting.report_helpers_classification", "_has_structural_risk"),
        "_has_symbolic_risk": ("r2morph.reporting.report_helpers_classification", "_has_symbolic_risk"),
        "_is_clean_pass": ("r2morph.reporting.report_helpers_classification", "_is_clean_pass"),
        "_is_covered_pass": ("r2morph.reporting.report_helpers_classification", "_is_covered_pass"),
        "_is_risky_pass": ("r2morph.reporting.report_helpers_classification", "_is_risky_pass"),
        "_is_uncovered_pass": ("r2morph.reporting.report_helpers_classification", "_is_uncovered_pass"),
        "_normalized_pass_map": ("r2morph.reporting.report_helpers", "_normalized_pass_map"),
        "_summary_first": ("r2morph.reporting.report_helpers", "_summary_first"),
        "resolve_general_symbolic_state": (
            "r2morph.reporting.report_state",
            "resolve_general_symbolic_state",
        ),
        "resolve_mismatch_view": ("r2morph.reporting.report_state", "resolve_mismatch_view"),
        "resolve_pass_filter_sets": ("r2morph.reporting.report_state", "resolve_pass_filter_sets"),
        "MutationResult": ("r2morph.reporting.sarif_formatter", "MutationResult"),
        "ReportData": ("r2morph.reporting.sarif_formatter", "ReportData"),
        "SARIFFormatter": ("r2morph.reporting.sarif_formatter", "SARIFFormatter"),
        "ValidationResult": ("r2morph.reporting.sarif_formatter", "ValidationResult"),
        "format_as_sarif": ("r2morph.reporting.sarif_formatter", "format_as_sarif"),
        "SARIFArtifact": ("r2morph.reporting.sarif_schema", "SARIFArtifact"),
        "SARIFArtifactLocation": ("r2morph.reporting.sarif_schema", "SARIFArtifactLocation"),
        "SARIFFileChange": ("r2morph.reporting.sarif_schema", "SARIFFileChange"),
        "SARIFFix": ("r2morph.reporting.sarif_schema", "SARIFFix"),
        "SARIFInvocation": ("r2morph.reporting.sarif_schema", "SARIFInvocation"),
        "SARIFLevel": ("r2morph.reporting.sarif_schema", "SARIFLevel"),
        "SARIFLocation": ("r2morph.reporting.sarif_schema", "SARIFLocation"),
        "SARIFLogicalLocation": ("r2morph.reporting.sarif_schema", "SARIFLogicalLocation"),
        "SARIFMessage": ("r2morph.reporting.sarif_schema", "SARIFMessage"),
        "SARIFNotification": ("r2morph.reporting.sarif_schema", "SARIFNotification"),
        "SARIFPhysicalLocation": ("r2morph.reporting.sarif_schema", "SARIFPhysicalLocation"),
        "SARIFRegion": ("r2morph.reporting.sarif_schema", "SARIFRegion"),
        "SARIFReplacement": ("r2morph.reporting.sarif_schema", "SARIFReplacement"),
        "SARIFReport": ("r2morph.reporting.sarif_schema", "SARIFReport"),
        "SARIFResult": ("r2morph.reporting.sarif_schema", "SARIFResult"),
        "SARIFRule": ("r2morph.reporting.sarif_schema", "SARIFRule"),
        "SARIFRun": ("r2morph.reporting.sarif_schema", "SARIFRun"),
        "SARIFSnippet": ("r2morph.reporting.sarif_schema", "SARIFSnippet"),
        "SARIFTool": ("r2morph.reporting.sarif_schema", "SARIFTool"),
        "SARIFToolComponent": ("r2morph.reporting.sarif_schema", "SARIFToolComponent"),
        "EvidenceAggregator": ("r2morph.reporting.summary_aggregator_evidence", "EvidenceAggregator"),
        "SummaryAggregator": ("r2morph.reporting.summary_aggregator_summary", "SummaryAggregator"),
        "SymbolicAggregator": ("r2morph.reporting.summary_aggregator_symbolic", "SymbolicAggregator"),
    }
    if name in _LAZY_RENDERING_NAMES:
        value = getattr(import_module("r2morph.reporting.report_rendering"), name)
        globals()[name] = value
        return value
    if name in lazy_exports:
        module_name, attr_name = lazy_exports[name]
        value = getattr(import_module(module_name), attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
