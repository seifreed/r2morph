from pathlib import Path

import pytest

from r2morph.core import randomness
from r2morph.validation.fuzzer import FuzzResult, MutationFuzzer
from tests.utils.assertions import expect

_EXPECTED_ARGS_RESULT_TOTAL_TESTS_2 = 2
_EXPECTED_RESULT_SUCCESS_RATE_75_0 = 75.0
_EXPECTED_RESULT_TOTAL_TESTS_2 = 2


def test_fuzz_result_string_and_success_rate():
    result = FuzzResult(
        total_tests=4,
        passed=3,
        failed=1,
        crashes=0,
        timeouts=0,
        validation_results=[],
    )
    expect(result.success_rate == _EXPECTED_RESULT_SUCCESS_RATE_75_0)
    text = str(result)
    expect(not ("Fuzz Results" not in text))
    expect(not ("Passed" not in text))


def test_fuzzer_generate_inputs_types():
    fuzzer = MutationFuzzer(num_tests=1, timeout=1)
    randomness.seed(0)

    expect(isinstance(fuzzer._generate_input("random"), str))
    expect(isinstance(fuzzer._generate_input("ascii"), str))
    expect(isinstance(fuzzer._generate_input("binary"), str))
    expect(isinstance(fuzzer._generate_input("structured"), str))
    expect(fuzzer._generate_input("unknown") == "")


def test_fuzzer_runs_on_real_binary(tmp_path: Path):
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    orig = tmp_path / "orig.bin"
    mut = tmp_path / "mut.bin"
    data = source.read_bytes()
    orig.write_bytes(data)
    mut.write_bytes(data)

    fuzzer = MutationFuzzer(num_tests=2, timeout=2)
    randomness.seed(1)
    result = fuzzer.fuzz(orig, mut, input_type="ascii")
    expect(isinstance(result, FuzzResult))
    expect(result.total_tests == _EXPECTED_RESULT_TOTAL_TESTS_2)

    randomness.seed(2)
    args_result = fuzzer.fuzz_with_args(orig, mut, arg_count=2)
    expect(args_result.total_tests == _EXPECTED_ARGS_RESULT_TOTAL_TESTS_2)
