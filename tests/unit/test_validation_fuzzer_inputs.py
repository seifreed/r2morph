from __future__ import annotations

from r2morph.validation.fuzzer import FuzzResult, MutationFuzzer
from tests.utils.assertions import expect

_EXPECTED_RESULT_SUCCESS_RATE_70_0 = 70.0


def test_fuzz_result_str_and_success_rate() -> None:
    result = FuzzResult(
        total_tests=10,
        passed=7,
        failed=3,
        crashes=1,
        timeouts=0,
        validation_results=[],
    )

    expect(result.success_rate == _EXPECTED_RESULT_SUCCESS_RATE_70_0)
    text = str(result)
    expect(not ("Fuzz Results" not in text))
    expect(not ("Passed: 7" not in text))


def test_fuzzer_input_generators() -> None:
    fuzzer = MutationFuzzer(num_tests=1, timeout=1)

    random_input = fuzzer._generate_input("random")
    ascii_input = fuzzer._generate_input("ascii")
    binary_input = fuzzer._generate_input("binary")
    structured_input = fuzzer._generate_input("structured")
    unknown_input = fuzzer._generate_input("unknown")

    expect(isinstance(random_input, str))
    expect(isinstance(ascii_input, str))
    expect(isinstance(binary_input, str))
    expect(isinstance(structured_input, str))
    expect(unknown_input == "")
