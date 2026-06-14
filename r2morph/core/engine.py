"""
Main morphing engine for binary transformations.
"""

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.constants import SEVERITY_ORDER as SEVERITY_ORDER
from r2morph.core.engine_lifecycle import analyze as analyze_lifecycle
from r2morph.core.engine_lifecycle import load_binary as load_binary_lifecycle
from r2morph.core.engine_mutations import add_mutation as add_mutation_lifecycle
from r2morph.core.engine_mutations import mutations as mutations_lifecycle
from r2morph.core.engine_mutations import remove_mutation as remove_mutation_lifecycle
from r2morph.core.engine_output import build_report as build_report_output
from r2morph.core.engine_output import save_binary as save_binary_output
from r2morph.core.engine_output import save_report as save_report_output
from r2morph.core.engine_run import run as run_lifecycle
from r2morph.core.engine_wiring import build_engine_wiring
from r2morph.core.report_helpers import (  # noqa: F401
    REPORT_SCHEMA_VERSION,
    _build_discarded_mutation_priority,
    _build_evidence_summary_for_pass,
    _build_observable_mismatch_map,
    _build_observable_mismatch_priority,
    _build_pass_capability_summary_map,
    _build_pass_region_evidence_map,
    _build_pass_triage_map,
    _build_pass_validation_context,
    _build_symbolic_summary_for_pass,
    _build_validation_role_map,
    _enrich_validation_policy,
    _summarize_degradation_roles,
    _summarize_diff_digest,
    _summarize_discarded_mutations,
    _summarize_observable_mismatches_by_pass,
    _summarize_pass_capability_rows,
    _summarize_pass_evidence,
    _summarize_pass_evidence_compact,
    _summarize_pass_risk_buckets,
    _summarize_pass_timings,
    _summarize_structural_evidence,
    _summarize_symbolic_coverage_by_pass,
    _summarize_symbolic_issue_passes,
    _summarize_symbolic_overview,
    _summarize_symbolic_severity_by_pass,
    _summarize_symbolic_statuses,
    _summarize_validation_adjustment_rows,
    _summarize_validation_adjustments,
    _summarize_validation_role_rows,
)
from r2morph.protocols import (
    BinarySignerProtocol,
    GateFailureReporterProtocol,
    MutationPassProtocol,
    PipelineProtocol,
    ReportBuilderProtocol,
    ReportViewBuilderProtocol,
)
from r2morph.session import MorphSession
from r2morph.validation import BinaryValidator

logger = logging.getLogger(__name__)


class MorphEngine:
    """
    Main engine for orchestrating binary transformations.

    The engine manages the binary analysis, applies mutation passes through
    a pipeline, and handles the output generation.

    Attributes:
        binary: Binary instance being transformed
        pipeline: Transformation pipeline
        config: Engine configuration
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        binary_signer: BinarySignerProtocol | None = None,
        gate_failure_reporter: GateFailureReporterProtocol | None = None,
        report_view_builder: ReportViewBuilderProtocol | None = None,
        report_builder: ReportBuilderProtocol | None = None,
    ) -> None:
        """
        Initialize the MorphEngine.

        Args:
            config: Optional configuration dictionary
            binary_signer: Optional post-save binary signer; defaults to the
                platform's signer (no-op off macOS)
            gate_failure_reporter: Optional gate-failure report summarizer;
                defaults to the reporting layer's implementation
            report_view_builder: Optional precomputed-report-views builder;
                defaults to the reporting layer's implementation
            report_builder: Optional report assembler; defaults to a
                ReportAssembler wired with the gate-failure reporter and
                report-view builder above
        """
        self.binary: Binary | None = None
        wiring = build_engine_wiring(
            binary_signer=binary_signer,
            gate_failure_reporter=gate_failure_reporter,
            report_view_builder=report_view_builder,
            report_builder=report_builder,
        )
        self.pipeline: PipelineProtocol = wiring.pipeline
        self._binary_signer: BinarySignerProtocol = wiring.binary_signer
        self._report_builder: ReportBuilderProtocol = wiring.report_builder
        self.config = config or {}
        self._stats: dict[str, Any] = {}
        self._memory_efficient_mode = False
        self._session: MorphSession | None = None
        self._last_result: dict[str, Any] | None = None

    @property
    def mutations(self) -> Sequence[MutationPassProtocol]:
        return mutations_lifecycle(self)

    def load_binary(self, path: str | Path, writable: bool = True) -> "MorphEngine":
        return load_binary_lifecycle(self, path, writable=writable)

    def analyze(self, level: str = "auto") -> "MorphEngine":
        return analyze_lifecycle(self, level)

    def _auto_detect_analysis_level(self) -> str:
        from r2morph.core.engine_lifecycle import auto_detect_analysis_level

        return auto_detect_analysis_level(self)

    def add_mutation(self, mutation: "MutationPassProtocol | str") -> "MorphEngine":
        return add_mutation_lifecycle(self, mutation)

    def remove_mutation(self, mutation_name: str) -> "MorphEngine":
        return remove_mutation_lifecycle(self, mutation_name)

    def run(
        self,
        *,
        validation_mode: str = "structural",
        rollback_policy: str = "skip-invalid-pass",
        checkpoint_per_mutation: bool = False,
        runtime_validator: BinaryValidator | None = None,
        runtime_validate_per_pass: bool = False,
        report_path: str | Path | None = None,
        seed: int | None = None,
    ) -> dict[str, Any]:
        return run_lifecycle(
            self,
            validation_mode=validation_mode,
            rollback_policy=rollback_policy,
            checkpoint_per_mutation=checkpoint_per_mutation,
            runtime_validator=runtime_validator,
            runtime_validate_per_pass=runtime_validate_per_pass,
            report_path=report_path,
            seed=seed,
        )

    def save(self, output_path: str | Path) -> None:
        save_binary_output(self, output_path)

    def close(self) -> None:
        """Close and cleanup resources."""
        if self.binary:
            self.binary.close()
            self.binary = None
        if self._session is not None:
            self._session.cleanup()
            self._session = None

    def get_stats(self) -> dict[str, Any]:
        """Get transformation statistics."""
        return self._stats

    def build_report(self, result: dict[str, Any] | None = None) -> dict[str, Any]:
        return build_report_output(self, result)

    def save_report(self, output_path: str | Path, result: dict[str, Any] | None = None) -> Path:
        return save_report_output(self, output_path, result)

    def __enter__(self) -> "MorphEngine":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()
