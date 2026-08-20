from __future__ import annotations

from pathlib import Path

from r2morph.validation.mutation_fuzzer_campaign import (
    build_exception_fuzz_result,
    build_success_fuzz_result,
    build_timeout_fuzz_result,
    save_failing_case,
)
from r2morph.validation.mutation_fuzzer_types import FuzzResult, FuzzTestCase
from tests.utils.assertions import expect

_EXPECTED_TIMEOUT_RESULT_EXECUTION_TIME_MS_3000 = 3000


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

    expect(
        result
        == FuzzResult(
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

    expect(timeout_result.execution_time_ms == _EXPECTED_TIMEOUT_RESULT_EXECUTION_TIME_MS_3000)
    expect(not (timeout_result.timeout is not True))
    expect(not (exception_result.crash is not True))
    expect(exception_result.original_error == "boom")


def test_save_failing_case_writes_json(tmp_path: Path) -> None:
    test_case = _test_case()
    result = build_exception_fuzz_result(
        test_case=test_case,
        error=RuntimeError("boom"),
        mutation_names=["nop"],
    )

    save_failing_case(test_case, result, tmp_path)

    saved = (tmp_path / "case-1_failure.json").read_text()
    expect(not ('"test_case"' not in saved))
    expect(not ('"result"' not in saved))
