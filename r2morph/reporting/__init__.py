"""
Reporting subpackage for report building, filtering, and rendering.

Extracted from cli.py and engine.py following Single Responsibility Principle.
"""

from r2morph.reporting.sarif_schema import (
    SARIFReport,
    SARIFRun,
    SARIFResult,
    SARIFRule,
    SARIFTool,
    SARIFToolComponent,
    SARIFArtifact,
    SARIFArtifactLocation,
    SARIFLocation,
    SARIFPhysicalLocation,
    SARIFRegion,
    SARIFMessage,
    SARIFLevel,
    SARIFFix,
    SARIFInvocation,
    SARIFNotification,
    SARIFSnippet,
    SARIFLogicalLocation,
    SARIFFileChange,
    SARIFReplacement,
)
from r2morph.reporting.sarif_formatter import (
    SARIFFormatter,
    MutationResult,
    ValidationResult,
    ReportData,
    format_as_sarif,
)
from r2morph.reporting.gate_evaluator import (
    SEVERITY_ORDER,
    GateEvaluator,
    GateFailure,
)
from r2morph.reporting.summary_aggregator import (
    SummaryAggregator,
    SymbolicAggregator,
    EvidenceAggregator,
)
from r2morph.reporting.report_filters import (
    ReportFilters,
    PassFilterResolver,
)
from r2morph.reporting.report_builder import (
    ReportBuilder,
    ReportContext,
    FilteredReport,
)
from r2morph.reporting.report_renderer import (
    ReportRenderer,
    ConsoleRenderer,
)
# Console rendering functions are lazily imported via __getattr__ below
# to avoid a circular import with r2morph.core.engine.
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

from r2morph.reporting.report_state import (
    resolve_general_symbolic_state,
    resolve_mismatch_view,
    resolve_pass_filter_sets,
    _normalized_pass_map,
    _summary_first,
    _is_risky_pass,
    _has_structural_risk,
    _has_symbolic_risk,
    _is_clean_pass,
    _is_covered_pass,
    _is_uncovered_pass,
)
from r2morph.reporting.report_emitter import (
    emit_report_payload,
    enforce_report_requirements,
    severity_threshold_met,
    report_view_has_results,
    gate_failure_result_count,
)

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


def __getattr__(name: str):
    """Lazily resolve rendering symbols to avoid circular imports."""
    if name in _LAZY_RENDERING_NAMES:
        from r2morph.reporting import report_rendering as _rr

        value = getattr(_rr, name)
        globals()[name] = value  # cache for subsequent access
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
