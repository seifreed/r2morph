"""Structured lifecycle events for mutation pipeline execution."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.utils.logging import log_exception_once


def log_pass_started(logger: logging.Logger, pass_name: str, index: int, total: int) -> None:
    """Record pass scheduling detail at debug level."""
    logger.debug(
        "Mutation pass started",
        extra={
            "event_name": "pipeline.pass.started",
            "operation": "pipeline.pass",
            "outcome": "started",
            "pass_name": pass_name,
            "pass_index": index,
            "pass_total": total,
        },
    )


def log_pass_failed(logger: logging.Logger, pass_name: str, error: Exception) -> None:
    """Record a pass failure once, while its exception context is active."""
    log_exception_once(
        logger,
        "Mutation pass failed",
        error,
        extra={
            "event_name": "pipeline.pass.failed",
            "operation": "pipeline.pass",
            "outcome": "failure",
            "pass_name": pass_name,
        },
    )


def log_pass_completed(logger: logging.Logger, pass_name: str, result: dict[str, Any]) -> None:
    """Record the observable outcome of one mutation pass."""
    rolled_back = bool(result.get("rolled_back", False))
    logger.info(
        "Mutation pass completed",
        extra={
            "event_name": "pipeline.pass.completed",
            "operation": "pipeline.pass",
            "outcome": "rolled_back" if rolled_back else "success",
            "status": "rolled_back" if rolled_back else "applied",
            "pass_name": pass_name,
            "mutation_count": int(result.get("mutations_applied", 0)),
            "duration_ms": round(float(result.get("execution_time_seconds", 0.0)) * 1000, 3),
        },
    )


def log_pipeline_completed(logger: logging.Logger, result: dict[str, Any]) -> None:
    """Record aggregate pipeline results without mutation payloads."""
    logger.info(
        "Mutation pipeline completed",
        extra={
            "event_name": "pipeline.completed",
            "operation": "pipeline.run",
            "outcome": "success" if not result["failed_passes"] else "partial_failure",
            "mutation_count": int(result["total_mutations"]),
            "failed_pass_count": int(result["failed_passes"]),
            "rolled_back_pass_count": int(result["rolled_back_passes"]),
        },
    )
