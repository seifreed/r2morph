"""Campaign helpers for mutation fuzzing."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

from r2morph.validation.mutation_fuzzer_types import FuzzCampaignResult, FuzzResult, FuzzTestCase

logger = logging.getLogger(__name__)


def build_success_fuzz_result(
    *,
    test_case: FuzzTestCase,
    result: Any,
    execution_time_ms: float,
    mutation_names: list[str],
) -> FuzzResult:
    """Build a successful fuzz result from a validator response."""
    return FuzzResult(
        test_id=test_case.test_id,
        passed=result.passed,
        original_exit_code=result.original_exitcode,
        mutated_exit_code=result.mutated_exitcode,
        original_output_hash=hashlib.sha256(result.original_output.encode()).hexdigest()[:16],
        mutated_output_hash=hashlib.sha256(result.mutated_output.encode()).hexdigest()[:16],
        original_error=result.to_dict().get("original_error", ""),
        mutated_error=result.to_dict().get("mutated_error", ""),
        execution_time_ms=execution_time_ms,
        crash=result.mutated_exitcode < 0 and "TIMEOUT" not in result.mutated_output,
        timeout="TIMEOUT" in result.mutated_output,
        mutation_count=len(mutation_names),
        mutation_names=mutation_names,
    )


def build_timeout_fuzz_result(
    *,
    test_case: FuzzTestCase,
    mutation_names: list[str],
    timeout_seconds: int,
) -> FuzzResult:
    """Build a fuzz result for a timed-out campaign iteration."""
    return FuzzResult(
        test_id=test_case.test_id,
        passed=False,
        original_exit_code=-1,
        mutated_exit_code=-1,
        original_output_hash="",
        mutated_output_hash="",
        original_error="Timeout",
        mutated_error="Timeout",
        execution_time_ms=timeout_seconds * 1000,
        crash=False,
        timeout=True,
        mutation_count=len(mutation_names),
        mutation_names=mutation_names,
    )


def build_exception_fuzz_result(
    *,
    test_case: FuzzTestCase,
    error: Exception,
    mutation_names: list[str],
) -> FuzzResult:
    """Build a fuzz result for an unexpected exception."""
    return FuzzResult(
        test_id=test_case.test_id,
        passed=False,
        original_exit_code=-1,
        mutated_exit_code=-1,
        original_output_hash="",
        mutated_output_hash="",
        original_error=str(error),
        mutated_error=str(error),
        execution_time_ms=0,
        crash=True,
        timeout=False,
        mutation_count=len(mutation_names),
        mutation_names=mutation_names,
    )


def build_campaign_result(
    *,
    total_tests: int,
    passed: int,
    failed: int,
    crashes: int,
    timeouts: int,
    results: list[FuzzResult],
    seed: int,
    config: Any,
    start_time: str,
    end_time: str,
    duration_seconds: float,
) -> FuzzCampaignResult:
    """Build the final campaign summary."""
    return FuzzCampaignResult(
        total_tests=total_tests,
        passed=passed,
        failed=failed,
        crashes=crashes,
        timeouts=timeouts,
        results=results,
        seed=seed,
        config=config,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=duration_seconds,
    )


def save_failing_case(test_case: FuzzTestCase, result: FuzzResult, output_dir: Path) -> None:
    """Save a failing test case for later analysis."""
    case_file = output_dir / f"{test_case.test_id}_failure.json"

    failure_data = {
        "test_case": asdict(test_case),
        "result": asdict(result),
    }

    with open(case_file, "w") as f:
        json.dump(failure_data, f, indent=2, default=str)

    logger.debug(f"Saved failing case: {case_file}")
