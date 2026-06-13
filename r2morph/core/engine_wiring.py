"""Composition-root wiring for MorphEngine."""

from __future__ import annotations

from dataclasses import dataclass

from r2morph.protocols import (
    BinarySignerProtocol,
    GateFailureReporterProtocol,
    PipelineProtocol,
    ReportBuilderProtocol,
    ReportViewBuilderProtocol,
)


@dataclass(frozen=True)
class EngineWiring:
    """Resolved MorphEngine dependencies."""

    pipeline: PipelineProtocol
    binary_signer: BinarySignerProtocol
    report_builder: ReportBuilderProtocol


def build_engine_wiring(
    *,
    binary_signer: BinarySignerProtocol | None = None,
    gate_failure_reporter: GateFailureReporterProtocol | None = None,
    report_view_builder: ReportViewBuilderProtocol | None = None,
    report_builder: ReportBuilderProtocol | None = None,
) -> EngineWiring:
    """Resolve MorphEngine dependencies without exposing construction details."""
    from r2morph.pipeline.pipeline import Pipeline
    from r2morph.platform.binary_signer import DarwinBinarySigner
    from r2morph.reporting.gate_evaluator import GateFailureReporter
    from r2morph.reporting.report_assembler import ReportAssembler
    from r2morph.reporting.report_view_builder import ReportViewBuilder

    resolved_gate_failure_reporter: GateFailureReporterProtocol = (
        gate_failure_reporter if gate_failure_reporter is not None else GateFailureReporter()
    )
    resolved_report_view_builder: ReportViewBuilderProtocol = (
        report_view_builder if report_view_builder is not None else ReportViewBuilder()
    )
    resolved_binary_signer: BinarySignerProtocol = (
        binary_signer if binary_signer is not None else DarwinBinarySigner()
    )
    resolved_report_builder: ReportBuilderProtocol = (
        report_builder
        if report_builder is not None
        else ReportAssembler(resolved_gate_failure_reporter, resolved_report_view_builder)
    )

    return EngineWiring(
        pipeline=Pipeline(),
        binary_signer=resolved_binary_signer,
        report_builder=resolved_report_builder,
    )
