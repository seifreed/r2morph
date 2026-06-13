"""
Main morphing engine for binary transformations.
"""

import logging
import random
import shutil
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.constants import SEVERITY_ORDER as SEVERITY_ORDER
from r2morph.core.engine_lifecycle import analyze as analyze_lifecycle
from r2morph.core.engine_lifecycle import load_binary as load_binary_lifecycle
from r2morph.core.report_helpers import (
    REPORT_SCHEMA_VERSION as REPORT_SCHEMA_VERSION,
)
from r2morph.core.report_helpers import (
    _build_discarded_mutation_priority as _build_discarded_mutation_priority,
)
from r2morph.core.report_helpers import (
    _build_evidence_summary_for_pass as _build_evidence_summary_for_pass,
)
from r2morph.core.report_helpers import (
    _build_observable_mismatch_map as _build_observable_mismatch_map,
)
from r2morph.core.report_helpers import (
    _build_observable_mismatch_priority as _build_observable_mismatch_priority,
)
from r2morph.core.report_helpers import (
    _build_pass_capability_summary_map as _build_pass_capability_summary_map,
)
from r2morph.core.report_helpers import (
    _build_pass_region_evidence_map as _build_pass_region_evidence_map,
)
from r2morph.core.report_helpers import (
    _build_pass_triage_map as _build_pass_triage_map,
)
from r2morph.core.report_helpers import (
    _build_pass_validation_context as _build_pass_validation_context,
)
from r2morph.core.report_helpers import (
    _build_symbolic_summary_for_pass as _build_symbolic_summary_for_pass,
)
from r2morph.core.report_helpers import (
    _build_validation_role_map as _build_validation_role_map,
)
from r2morph.core.report_helpers import (
    _enrich_validation_policy as _enrich_validation_policy,
)
from r2morph.core.report_helpers import (
    _summarize_degradation_roles as _summarize_degradation_roles,
)
from r2morph.core.report_helpers import (
    _summarize_diff_digest as _summarize_diff_digest,
)
from r2morph.core.report_helpers import (
    _summarize_discarded_mutations as _summarize_discarded_mutations,
)
from r2morph.core.report_helpers import (
    _summarize_normalized_pass_results as _summarize_normalized_pass_results,
)
from r2morph.core.report_helpers import (
    _summarize_observable_mismatches_by_pass as _summarize_observable_mismatches_by_pass,
)
from r2morph.core.report_helpers import (
    _summarize_pass_capability_rows as _summarize_pass_capability_rows,
)
from r2morph.core.report_helpers import (
    _summarize_pass_coverage_buckets as _summarize_pass_coverage_buckets,
)
from r2morph.core.report_helpers import (
    _summarize_pass_evidence as _summarize_pass_evidence,
)
from r2morph.core.report_helpers import (
    _summarize_pass_evidence_compact as _summarize_pass_evidence_compact,
)
from r2morph.core.report_helpers import (
    _summarize_pass_risk_buckets as _summarize_pass_risk_buckets,
)
from r2morph.core.report_helpers import (
    _summarize_pass_timings as _summarize_pass_timings,
)
from r2morph.core.report_helpers import (
    _summarize_pass_triage_rows as _summarize_pass_triage_rows,
)
from r2morph.core.report_helpers import (
    _summarize_structural_evidence as _summarize_structural_evidence,
)
from r2morph.core.report_helpers import (
    _summarize_symbolic_coverage_by_pass as _summarize_symbolic_coverage_by_pass,
)
from r2morph.core.report_helpers import (
    _summarize_symbolic_issue_passes as _summarize_symbolic_issue_passes,
)
from r2morph.core.report_helpers import (
    _summarize_symbolic_overview as _summarize_symbolic_overview,
)
from r2morph.core.report_helpers import (
    _summarize_symbolic_severity_by_pass as _summarize_symbolic_severity_by_pass,
)
from r2morph.core.report_helpers import (
    _summarize_symbolic_statuses as _summarize_symbolic_statuses,
)
from r2morph.core.report_helpers import (
    _summarize_validation_adjustment_rows as _summarize_validation_adjustment_rows,
)
from r2morph.core.report_helpers import (
    _summarize_validation_adjustments as _summarize_validation_adjustments,
)
from r2morph.core.report_helpers import (
    _summarize_validation_role_rows as _summarize_validation_role_rows,
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
from r2morph.validation import BinaryValidator, ValidationManager

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

        self.binary: Binary | None = None
        self.pipeline: PipelineProtocol = Pipeline()
        self._binary_signer: BinarySignerProtocol = binary_signer if binary_signer is not None else DarwinBinarySigner()
        self._report_builder: ReportBuilderProtocol = (
            report_builder
            if report_builder is not None
            else ReportAssembler(resolved_gate_failure_reporter, resolved_report_view_builder)
        )
        self.config = config or {}
        self._stats: dict[str, Any] = {}
        self._memory_efficient_mode = False
        self._session: MorphSession | None = None
        self._last_result: dict[str, Any] | None = None

    @property
    def mutations(self) -> Sequence[MutationPassProtocol]:
        """
        Get the registered mutation passes.

        Returns:
            Registered mutation passes in the pipeline
        """
        return self.pipeline.passes

    def load_binary(self, path: str | Path, writable: bool = True) -> "MorphEngine":
        return load_binary_lifecycle(self, path, writable=writable)

    def analyze(self, level: str = "auto") -> "MorphEngine":
        return analyze_lifecycle(self, level)

    def _auto_detect_analysis_level(self) -> str:
        from r2morph.core.engine_lifecycle import auto_detect_analysis_level

        return auto_detect_analysis_level(self)

    def add_mutation(self, mutation: "MutationPassProtocol | str") -> "MorphEngine":
        """
        Add a mutation pass to the pipeline.

        Automatically adjusts mutation parameters when in memory-efficient mode.

        Args:
            mutation: Mutation pass instance or pass name (e.g. "nop", "substitute",
                      "register", "expand", "block")

        Returns:
            Self for method chaining
        """
        if isinstance(mutation, str):
            mutation = self._resolve_mutation_pass(mutation)
        # Adjust mutation config for large binaries to prevent OOM
        if self._memory_efficient_mode:
            mutation.configure_for_memory_constraints(0.4)

        self.pipeline.add_pass(mutation)
        logger.debug(f"Added mutation: {mutation.__class__.__name__}")
        return self

    @staticmethod
    def _resolve_mutation_pass(name: str) -> MutationPassProtocol:
        """Resolve a mutation pass name to an instance."""
        from r2morph.mutations import (
            BlockReorderingPass,
            InstructionExpansionPass,
            InstructionSubstitutionPass,
            NopInsertionPass,
            RegisterSubstitutionPass,
        )

        pass_map: dict[str, type] = {
            "nop": NopInsertionPass,
            "substitute": InstructionSubstitutionPass,
            "register": RegisterSubstitutionPass,
            "expand": InstructionExpansionPass,
            "block": BlockReorderingPass,
        }
        cls = pass_map.get(name)
        if cls is None:
            raise ValueError(f"Unknown mutation pass: {name!r}. Valid names: {list(pass_map)}")
        result: MutationPassProtocol = cls()
        return result

    def remove_mutation(self, mutation_name: str) -> "MorphEngine":
        """
        Remove a mutation pass from the pipeline by name.

        Args:
            mutation_name: Name of the mutation to remove

        Returns:
            Self for method chaining
        """
        self.pipeline.remove_pass_by_name(mutation_name)
        logger.debug(f"Removed mutation: {mutation_name}")
        return self

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
        """
        Run the transformation pipeline on the binary.

        Returns:
            Dictionary with transformation statistics and results
        """
        if not self.binary:
            raise RuntimeError("No binary loaded. Call load_binary() first.")

        if not self.binary.is_analyzed():
            logger.warning("Binary not analyzed. Running automatic analysis...")
            self.analyze()

        logger.info("Starting transformation pipeline...")
        start_time = time.time()
        if seed is not None:
            self.config["seed"] = int(seed)
            random.seed(seed)
            for index, mutation in enumerate(self.pipeline.passes):
                pass_seed = int(seed) + index
                mutation.config["_pass_seed"] = pass_seed
                mutation.config["_use_derived_seed"] = True

        validation_manager = None
        if validation_mode not in {"off", "runtime"}:
            validation_manager = ValidationManager(mode=validation_mode)

        result = self.pipeline.run(
            self.binary,
            session=self._session,
            validation_manager=validation_manager,
            runtime_validator=runtime_validator,
            runtime_validate_per_pass=runtime_validate_per_pass or validation_mode == "runtime",
            rollback_policy=rollback_policy,
            checkpoint_per_mutation=checkpoint_per_mutation,
        )

        if runtime_validator is not None and self._original_path is not None:
            assert self.binary is not None
            runtime_result = runtime_validator.validate(self._original_path, self.binary.path)
            result["validation"]["runtime"] = runtime_result.to_dict()
            result["validation"]["all_passed"] = result["validation"].get("all_passed", True) and runtime_result.passed
            if not runtime_result.passed and self._session is not None:
                self._session.rollback_to("initial")
                self.binary.reload()
                if rollback_policy == "fail-fast":
                    raise RuntimeError("Runtime validation failed after pipeline execution")

        requested_validation_mode = self.config.get("requested_validation_mode", validation_mode)
        effective_validation_mode = self.config.get("effective_validation_mode", validation_mode)
        validation_policy = self.config.get("validation_policy")
        for pass_name, pass_result in result.get("pass_results", {}).items():
            pass_result["validation_context"] = _build_pass_validation_context(
                pass_name,
                requested_mode=requested_validation_mode,
                effective_mode=effective_validation_mode,
                validation_policy=validation_policy,
            )
        result["requested_validation_mode"] = requested_validation_mode
        result["validation_mode"] = effective_validation_mode
        enriched_validation_policy = _enrich_validation_policy(
            validation_policy,
            result.get("pass_results", {}),
        )
        if enriched_validation_policy is not None:
            result["validation_policy"] = enriched_validation_policy
        result["execution_time_seconds"] = round(time.time() - start_time, 3)
        assert self.binary is not None
        result["input_path"] = str(self._original_path or self.binary.path)
        result["working_path"] = str(self.binary.path)
        result["config"] = dict(self.config)
        self._last_result = {**self._stats, **result}

        if report_path is not None:
            self.save_report(report_path, self._last_result)

        logger.info("Transformation complete")
        return self._last_result

    def save(self, output_path: str | Path) -> None:
        """
        Save the transformed binary.

        Args:
            output_path: Output file path
        """
        if not self.binary:
            raise RuntimeError("No binary loaded.")

        output_path = Path(output_path)

        logger.info(f"Saving transformed binary to: {output_path}")

        if self._session is not None:
            self._session.finalize(output_path)
        else:
            assert self.binary is not None
            shutil.copy2(self.binary.path, output_path)
            logger.info(f"Binary successfully saved to: {output_path}")

        self._binary_signer.sign_output(output_path, self.config)

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
        """Build a stable machine-readable engine report."""
        return self._report_builder.assemble_report(
            result,
            pipeline_passes=self.pipeline.passes,
            last_result=self._last_result,
        )

    def save_report(self, output_path: str | Path, result: dict[str, Any] | None = None) -> Path:
        """Save a JSON report for the last engine run."""
        import json

        output = Path(output_path)
        report = self.build_report(result)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        logger.info(f"Saved engine report to: {output}")
        return output

    def __enter__(self) -> "MorphEngine":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()
