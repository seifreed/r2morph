from __future__ import annotations

from pathlib import Path

from r2morph.validation.mutation_fuzzer_campaign import (
    build_campaign_result,
    build_exception_fuzz_result,
    build_success_fuzz_result,
    build_timeout_fuzz_result,
    save_failing_case,
)
from r2morph.validation.mutation_fuzzer_types import FuzzCampaignResult, FuzzConfig, FuzzResult, FuzzTestCase


class _ValidationResult:
    def __init__(self) -> None:
        self.passed = True
        self.original_exitcode = 0
        self.mutated_exitcode = 1
        self.original_output = "ok"
        self.mutated_output = "TIMEOUT\n"

    def to_dict(self) -> dict[str, str]:
        return {"original_error": "", "mutated_error": "boom"}


def _test_case() -> FuzzTestCase:
    return FuzzTestCase(
        test_id="case-1",
        input_data=b"payload",
        input_type="structured",
        args=["--flag"],
        env={"K": "V"},
        description="demo case",
    )


def test_build_success_fuzz_result_maps_validator_output() -> None:
    result = build_success_fuzz_result(
        test_case=_test_case(),
        result=_ValidationResult(),
        execution_time_ms=12.5,
        mutation_names=["nop", "register"],
    )

    assert result == FuzzResult(
        test_id="case-1",
        passed=True,
        original_exit_code=0,
        mutated_exit_code=1,
        original_output_hash="2689367b205c16ce",
        mutated_output_hash="1d44ad7979d972df",
        original_error="",
        mutated_error="boom",
        execution_time_ms=12.5,
        crash=False,
        timeout=True,
        mutation_count=2,
        mutation_names=["nop", "register"],
    )


def test_build_timeout_and_exception_results() -> None:
    timeout_result = build_timeout_fuzz_result(
        test_case=_test_case(),
        mutation_names=["nop"],
        timeout_seconds=3,
    )
    exception_result = build_exception_fuzz_result(
        test_case=_test_case(),
        error=RuntimeError("boom"),
        mutation_names=["nop"],
    )

    assert timeout_result.execution_time_ms == 3000
    assert timeout_result.timeout is True
    assert exception_result.crash is True
    assert exception_result.original_error == "boom"


def test_build_campaign_result_preserves_metadata() -> None:
    result = build_campaign_result(
        total_tests=5,
        passed=4,
        failed=1,
        crashes=0,
        timeouts=1,
        results=[],
        seed=123,
        config=FuzzConfig(num_tests=5, timeout=2, seed=123),
        start_time="2024-01-01T00:00:00",
        end_time="2024-01-01T00:00:10",
        duration_seconds=10.0,
    )

    assert isinstance(result, FuzzCampaignResult)
    assert result.seed == 123
    assert result.config.num_tests == 5
    assert result.success_rate == 80.0


def test_save_failing_case_writes_json(tmp_path: Path) -> None:
    test_case = _test_case()
    result = build_exception_fuzz_result(
        test_case=test_case,
        error=RuntimeError("boom"),
        mutation_names=["nop"],
    )

    save_failing_case(test_case, result, tmp_path)

    saved = (tmp_path / "case-1_failure.json").read_text()
    assert '"test_case"' in saved
    assert '"result"' in saved
