"""
Factory functions for dependency injection following SOLID principles.

This module provides factory functions that create properly configured instances
while respecting Interface Segregation Principle (ISP).

Usage:
    from r2morph.factories import create_binary_reader, create_report_emitter

    reader = create_binary_reader(r2_connection)
    emitter = create_report_emitter(console=Console())
"""

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from rich.console import Console


def create_binary_reader(
    r2: Any,
    lazy_load: bool = True,
):
    """
    Factory function for BinaryReader.

    Args:
        r2: r2pipe connection instance
        lazy_load: Whether to use lazy loading for functions

    Returns:
        Configured BinaryReader instance
    """
    from r2morph.core.reader import BinaryReader

    return BinaryReader(r2)


def create_binary_writer(
    r2: Any,
    path: Path,
    writable: bool = False,
):
    """
    Factory function for BinaryWriter.

    Args:
        r2: r2Pipe connection instance
        path: Path to the binary file
        writable: Whether the binary was opened in write mode

    Returns:
        Configured BinaryWriter instance
    """
    from r2morph.core.writer import BinaryWriter

    return BinaryWriter(r2, path, writable)


def create_assembly_service():
    """
    Factory function for AssemblyService.

    Returns:
        Configured AssemblyService instance
    """
    from r2morph.core.assembly import get_assembly_service

    return get_assembly_service()


def create_memory_manager(
    batch_size: int = 1000,
    low_memory: bool = False,
):
    """
    Factory function for MemoryManager.

    Args:
        batch_size: Number of mutations before checkpoint
        low_memory: Whether to enable low memory mode

    Returns:
        Configured MemoryManager instance
    """
    from r2morph.core.memory_manager import get_memory_manager

    return get_memory_manager()


def create_report_emitter(
    console: Console | None = None,
):
    """
    Factory function for report emission.

    Args:
        console: Optional Console instance (creates new if None)

    Returns:
        Dict with emit functions
    """
    from r2morph.reporting.report_emitter import (
        emit_report_payload,
        enforce_report_requirements,
    )

    c = console or Console()

    def emit(
        filtered_payload: dict[str, Any],
        output: Path | None,
        summary_only: bool,
    ) -> None:
        return emit_report_payload(
            filtered_payload=filtered_payload,
            output=output,
            summary_only=summary_only,
            console_instance=c,
        )

    def enforce(
        require_results: bool,
        severity_rows: list[dict[str, Any]],
        min_severity_rank: int | None,
        mutation_count: int,
        **kwargs: Any,
    ) -> None:
        return enforce_report_requirements(
            require_results=require_results,
            severity_rows=severity_rows,
            min_severity_rank=min_severity_rank,
            mutation_count=mutation_count,
            **kwargs,
        )

    return {
        "emit": emit,
        "enforce": enforce,
    }


def create_console_renderer(
    console: Console | None = None,
):
    """
    Factory function for console rendering.

    Args:
        console: Optional Console instance (creates new if None)

    Returns:
        Dict with render functions
    """
    from r2morph.reporting.console_renderer import (
        render_pass_capabilities,
        render_pass_validation_contexts,
        render_symbolic_sections,
        render_gate_sections,
        render_degradation_sections,
        render_only_mismatches_sections,
        render_only_pass_sections,
        render_report_filter_messages,
        render_summary_table,
        render_gate_evaluation_sections,
        render_general_report_sections,
        render_general_only_pass_sections,
        render_mismatch_summary_sections,
        render_validation_context_table,
    )

    c = console or Console()

    def render_capabilities(capabilities: list[dict[str, Any]]) -> None:
        return render_pass_capabilities(capabilities, console=c)

    def render_contexts(contexts: list[dict[str, Any]]) -> None:
        return render_pass_validation_contexts(contexts, console=c)

    def render_symbolic(
        requested: int,
        match: int,
        mismatch: int,
        bounded: int,
        without_coverage: int,
    ) -> None:
        return render_symbolic_sections(
            requested,
            match,
            mismatch,
            bounded,
            without_coverage,
            console=c,
        )

    def render_gate(summary: dict[str, Any], priority: list[dict[str, Any]]) -> None:
        return render_gate_sections(summary, priority, console=c)

    def render_degradation(summary: dict[str, Any]) -> None:
        return render_degradation_sections(summary, console=c)

    def render_summary(summary: dict[str, Any]) -> None:
        return render_summary_table(summary, console=c)

    return {
        "render_pass_capabilities": render_capabilities,
        "render_pass_validation_contexts": render_contexts,
        "render_symbolic_sections": render_symbolic,
        "render_gate_sections": render_gate,
        "render_degradation_sections": render_degradation,
        "render_summary_table": render_summary,
        "render_only_mismatches_sections": lambda rows: render_only_mismatches_sections(
            rows, console=c
        ),
        "render_only_pass_sections": lambda name, data: render_only_pass_sections(
            name, data, console=c
        ),
        "render_report_filter_messages": lambda *args, **kw: render_report_filter_messages(
            *args, console=c, **kw
        ),
        "render_gate_evaluation_sections": lambda *args, **kw: render_gate_evaluation_sections(
            *args, console=c, **kw
        ),
        "render_general_report_sections": lambda *args, **kw: render_general_report_sections(
            *args, console=c, **kw
        ),
        "render_general_only_pass_sections": lambda *args, **kw: render_general_only_pass_sections(
            *args, console=c, **kw
        ),
        "render_mismatch_summary_sections": lambda *args, **kw: render_mismatch_summary_sections(
            *args, console=c, **kw
        ),
        "render_validation_context_table": lambda *args, **kw: render_validation_context_table(
            *args, console=c, **kw
        ),
    }


def create_gate_evaluator():
    """
    Factory function for GateEvaluator.

    Returns:
        GateEvaluator class (stateless, can be reused)
    """
    from r2morph.reporting.gate_evaluator import GateEvaluator

    return GateEvaluator


def create_summary_aggregator():
    """
    Factory function for SummaryAggregator.

    Returns:
        SummaryAggregator instance
    """
    from r2morph.reporting.summary_aggregator import SummaryAggregator

    return SummaryAggregator()


def create_symbolic_aggregator():
    """
    Factory function for SymbolicAggregator.

    Returns:
        SymbolicAggregator class (stateless, can be reused)
    """
    from r2morph.reporting.summary_aggregator import SymbolicAggregator

    return SymbolicAggregator


def create_evidence_aggregator():
    """
    Factory function for EvidenceAggregator.

    Returns:
        EvidenceAggregator class (stateless, can be reused)
    """
    from r2morph.reporting.summary_aggregator import EvidenceAggregator

    return EvidenceAggregator


def create_report_builder():
    """
    Factory function for ReportBuilder.

    Returns:
        ReportBuilder class (stateless, can be reused)
    """
    from r2morph.reporting.report_builder import ReportBuilder

    return ReportBuilder


def create_pass_filter_resolver():
    """
    Factory function for PassFilterResolver.

    Returns:
        PassFilterResolver class (stateless, can be reused)
    """
    from r2morph.reporting.report_filters import PassFilterResolver

    return PassFilterResolver


def create_report_filters():
    """
    Factory function for ReportFilters.

    Returns:
        ReportFilters class (stateless, can be reused)
    """
    from r2morph.reporting.report_filters import ReportFilters

    return ReportFilters


__all__ = [
    "create_binary_reader",
    "create_binary_writer",
    "create_assembly_service",
    "create_memory_manager",
    "create_report_emitter",
    "create_console_renderer",
    "create_gate_evaluator",
    "create_summary_aggregator",
    "create_symbolic_aggregator",
    "create_evidence_aggregator",
    "create_report_builder",
    "create_pass_filter_resolver",
    "create_report_filters",
]
