"""Run helpers extracted from MorphEngine."""

from __future__ import annotations

import logging
import random
import time
from pathlib import Path
from typing import Any

from r2morph.core.report_helpers import _build_pass_validation_context, _enrich_validation_policy
from r2morph.validation import BinaryValidator, ValidationManager

logger = logging.getLogger(__name__)


def _apply_seed_to_passes(engine: Any, seed: int) -> None:
    engine.config["seed"] = int(seed)
    random.seed(seed)
    for index, mutation in enumerate(engine.pipeline.passes):
        pass_seed = int(seed) + index
        mutation.config["_pass_seed"] = pass_seed
        mutation.config["_use_derived_seed"] = True


def _build_validation_manager(validation_mode: str) -> ValidationManager | None:
    if validation_mode in {"off", "runtime"}:
        return None
    return ValidationManager(mode=validation_mode)


def _apply_runtime_validation(
    engine: Any,
    result: dict[str, Any],
    runtime_validator: BinaryValidator | None,
    rollback_policy: str,
) -> None:
    if runtime_validator is None or engine._original_path is None:
        return

    assert engine.binary is not None
    runtime_result = runtime_validator.validate(engine._original_path, engine.binary.path)
    result["validation"]["runtime"] = runtime_result.to_dict()
    result["validation"]["all_passed"] = result["validation"].get("all_passed", True) and runtime_result.passed
    if not runtime_result.passed and engine._session is not None:
        engine._session.rollback_to("initial")
        engine.binary.reload()
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
    assert engine.binary is not None
    result["input_path"] = str(engine._original_path or engine.binary.path)
    result["working_path"] = str(engine.binary.path)
    result["config"] = dict(engine.config)


def run(
    engine: Any,
    *,
    validation_mode: str = "structural",
    rollback_policy: str = "skip-invalid-pass",
    checkpoint_per_mutation: bool = False,
    runtime_validator: BinaryValidator | None = None,
    runtime_validate_per_pass: bool = False,
    report_path: str | Path | None = None,
    seed: int | None = None,
) -> dict[str, Any]:
    """Run the transformation pipeline using the engine state."""
    if not engine.binary:
        raise RuntimeError("No binary loaded. Call load_binary() first.")

    if not engine.binary.is_analyzed():
        logger.warning("Binary not analyzed. Running automatic analysis...")
        engine.analyze()

    logger.info("Starting transformation pipeline...")
    start_time = time.time()
    if seed is not None:
        _apply_seed_to_passes(engine, seed)

    validation_manager = _build_validation_manager(validation_mode)

    result = engine.pipeline.run(
        engine.binary,
        session=engine._session,
        validation_manager=validation_manager,
        runtime_validator=runtime_validator,
        runtime_validate_per_pass=runtime_validate_per_pass or validation_mode == "runtime",
        rollback_policy=rollback_policy,
        checkpoint_per_mutation=checkpoint_per_mutation,
    )

    _apply_runtime_validation(engine, result, runtime_validator, rollback_policy)
    _enrich_run_result(engine, result, validation_mode, start_time)
    engine._last_result = {**engine._stats, **result}

    if report_path is not None:
        engine.save_report(report_path, engine._last_result)

    logger.info("Transformation complete")
    return engine._last_result
