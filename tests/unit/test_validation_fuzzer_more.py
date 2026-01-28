import random
from pathlib import Path

import pytest

from r2morph.validation.fuzzer import MutationFuzzer, FuzzResult


def test_fuzz_result_string_and_success_rate():
    result = FuzzResult(
        total_tests=4,
        passed=3,
        failed=1,
        crashes=0,
        timeouts=0,
        validation_results=[],
    )
    assert result.success_rate == 75.0
    text = str(result)
    assert "Fuzz Results" in text
    assert "Passed" in text


def test_fuzzer_generate_inputs_types():
    fuzzer = MutationFuzzer(num_tests=1, timeout=1)
    random.seed(0)

    assert isinstance(fuzzer._generate_input("random"), str)
    assert isinstance(fuzzer._generate_input("ascii"), str)
    assert isinstance(fuzzer._generate_input("binary"), str)
    assert isinstance(fuzzer._generate_input("structured"), str)
    assert fuzzer._generate_input("unknown") == ""


def test_fuzzer_runs_on_real_binary(tmp_path: Path):
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    orig = tmp_path / "orig.bin"
    mut = tmp_path / "mut.bin"
    data = source.read_bytes()
    orig.write_bytes(data)
    mut.write_bytes(data)

    fuzzer = MutationFuzzer(num_tests=2, timeout=2)
    random.seed(1)
    result = fuzzer.fuzz(orig, mut, input_type="ascii")
    assert isinstance(result, FuzzResult)
    assert result.total_tests == 2

    random.seed(2)
    args_result = fuzzer.fuzz_with_args(orig, mut, arg_count=2)
    assert args_result.total_tests == 2
