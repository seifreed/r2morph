from __future__ import annotations

from r2morph.validation.fuzzer import FuzzResult, MutationFuzzer


def test_fuzz_result_str_and_success_rate() -> None:
    result = FuzzResult(
        total_tests=10,
        passed=7,
        failed=3,
        crashes=1,
        timeouts=0,
        validation_results=[],
    )

    assert result.success_rate == 70.0
    text = str(result)
    assert "Fuzz Results" in text
    assert "Passed: 7" in text


def test_fuzzer_input_generators() -> None:
    fuzzer = MutationFuzzer(num_tests=1, timeout=1)

    random_input = fuzzer._generate_input("random")
    ascii_input = fuzzer._generate_input("ascii")
    binary_input = fuzzer._generate_input("binary")
    structured_input = fuzzer._generate_input("structured")
    unknown_input = fuzzer._generate_input("unknown")

    assert isinstance(random_input, str)
    assert isinstance(ascii_input, str)
    assert isinstance(binary_input, str)
    assert isinstance(structured_input, str)
    assert unknown_input == ""
