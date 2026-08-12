"""Run helpers extracted from MorphEngine."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import r2morph.core.randomness as random
from r2morph.core.report_helpers_validation import _build_pass_validation_context, _enrich_validation_policy
from r2morph.protocols import PipelineRunOptions
from r2morph.validation import BinaryValidator, ValidationManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EngineRunOptions:
    validation_mode: str = "structural"
    rollback_policy: str = "skip-invalid-pass"
    checkpoint_per_mutation: bool = False
    validation_manager: ValidationManager | None = None
    runtime_validator: BinaryValidator | None = None
    runtime_validate_per_pass: bool = False
    report_path: str | Path | None = None
    seed: int | None = None


def _apply_seed_to_passes(engine: Any, seed: int) -> None:
    engine.config["seed"] = int(seed)
    random.seed(seed)
    for index, mutation in enumerate(engine.pipeline.passes):
        pass_seed = int(seed) + index
        mutation.config["_pass_seed"] = pass_seed
        mutation.config["_use_derived_seed"] = True


def _build_validation_manager(
    validation_mode: str,
    validation_manager: ValidationManager | None = None,
) -> ValidationManager | None:
    if validation_mode in {"off", "runtime"}:
        return None
    return validation_manager or ValidationManager(mode=validation_mode)


def _apply_runtime_validation(
    engine: Any,
    result: dict[str, Any],
    runtime_validator: BinaryValidator | None,
    rollback_policy: str,
) -> None:
    if runtime_validator is None or engine._original_path is None:
        return

    binary = engine.binary
    if binary is None:
        raise RuntimeError("No binary loaded. Call load_binary() first.")
    runtime_result = runtime_validator.validate(engine._original_path, binary.path)
    result["validation"]["runtime"] = runtime_result.to_dict()
    result["validation"]["all_passed"] = result["validation"].get("all_passed", True) and runtime_result.passed
    if not runtime_result.passed and engine._session is not None:
        engine._session.rollback_to("initial")
        binary.reload()
        if rollback_policy == "fail-fast":
            raise RuntimeError("Runtime validation failed after pipeline execution")


def _enrich_run_result(engine: Any, result: dict[str, Any], validation_mode: str, start_time: float) -> None:
    requested_validation_mode = engine.config.get("requested_validation_mode", validation_mode)
    effective_validation_mode = engine.config.get("effective_validation_mode", validation_mode)
    validation_policy = engine.config.get("validation_policy")

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
    binary = engine.binary
    if binary is None:
        raise RuntimeError("No binary loaded. Call load_binary() first.")
    result["input_path"] = str(engine._original_path or binary.path)
    result["working_path"] = str(binary.path)
    result["config"] = dict(engine.config)


def run(engine: Any, options: EngineRunOptions | None = None) -> dict[str, Any]:
    """Run the transformation pipeline using the engine state."""
    options = options or EngineRunOptions()
    if not engine.binary:
        raise RuntimeError("No binary loaded. Call load_binary() first.")

    if not engine.binary.is_analyzed():
        logger.warning("Binary not analyzed. Running automatic analysis...")
        engine.analyze()

    logger.info("Starting transformation pipeline...")
    start_time = time.time()
    if options.seed is not None:
        _apply_seed_to_passes(engine, options.seed)

    validation_manager = _build_validation_manager(options.validation_mode, options.validation_manager)

    result = engine.pipeline.run(
        engine.binary,
        PipelineRunOptions(
            session=engine._session,
            validation_manager=validation_manager,
            runtime_validator=options.runtime_validator,
            runtime_validate_per_pass=options.runtime_validate_per_pass or options.validation_mode == "runtime",
            rollback_policy=options.rollback_policy,
            checkpoint_per_mutation=options.checkpoint_per_mutation,
        ),
    )

    _apply_runtime_validation(engine, result, options.runtime_validator, options.rollback_policy)
    _enrich_run_result(engine, result, options.validation_mode, start_time)
    engine._last_result = {**engine._stats, **result}

    if options.report_path is not None:
        engine.save_report(options.report_path, engine._last_result)

    logger.info("Transformation complete")
    return cast("dict[str, Any]", engine._last_result)
