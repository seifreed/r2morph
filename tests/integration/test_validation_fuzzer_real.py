from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.validation.fuzzer import MutationFuzzer
from tests.utils.assertions import expect

_EXPECTED_ARGS_RESULT_TOTAL_TESTS_3 = 3
_EXPECTED_RESULT_TOTAL_TESTS_3 = 3


def test_mutation_fuzzer_with_random_inputs(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("Binary execution test requires macOS")

    source = Path("fixtures/dataset/macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    original = tmp_path / "orig"
    mutated = tmp_path / "mut"
    original.write_bytes(source.read_bytes())
    mutated.write_bytes(source.read_bytes())

    fuzzer = MutationFuzzer(num_tests=3, timeout=3)
    result = fuzzer.fuzz(original, mutated, input_type="ascii")
    expect(result.total_tests == _EXPECTED_RESULT_TOTAL_TESTS_3)
    expect(result.passed + result.failed == result.total_tests)
    expect(not (result.success_rate < 0.0))

    args_result = fuzzer.fuzz_with_args(original, mutated, arg_count=2)
    expect(args_result.total_tests == _EXPECTED_ARGS_RESULT_TOTAL_TESTS_3)
