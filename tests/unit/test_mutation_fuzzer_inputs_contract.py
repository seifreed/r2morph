from __future__ import annotations

import random

from r2morph.validation.mutation_fuzzer import MutationPassFuzzer
from r2morph.validation.mutation_fuzzer_inputs import (
    generate_ascii_input,
    generate_binary_input,
    generate_edge_case_input,
    generate_format_string_input,
    generate_path_like_input,
    generate_random_input,
    generate_structured_input,
    generate_test_case,
)
from r2morph.validation.mutation_fuzzer_types import FuzzConfig


def test_input_helpers_return_bytes() -> None:
    config = FuzzConfig(num_tests=1, timeout=1, seed=1, min_input_size=4, max_input_size=8)

    random.seed(1)
    assert isinstance(generate_random_input(config, 8), bytes)
    assert isinstance(generate_ascii_input(config, 8), bytes)
    assert isinstance(generate_binary_input(config, 8), bytes)
    assert isinstance(generate_structured_input(config, 8), bytes)
    assert isinstance(generate_edge_case_input(config, 8), bytes)
    assert isinstance(generate_format_string_input(config, 8), bytes)
    assert isinstance(generate_path_like_input(config, 8), bytes)


def test_generate_test_case_uses_expected_contract() -> None:
    config = FuzzConfig(num_tests=1, timeout=1, seed=7, min_input_size=4, max_input_size=8)

    random.seed(7)
    test_case = generate_test_case(config, 3)

    assert test_case.test_id == "fuzz_0003"
    assert isinstance(test_case.input_data, bytes)
    assert isinstance(test_case.args, list)
    assert isinstance(test_case.env, dict)


def test_mutation_pass_fuzzer_delegates_to_input_helpers() -> None:
    fuzzer = MutationPassFuzzer(FuzzConfig(seed=11, min_input_size=4, max_input_size=8))

    random.seed(11)
    generated = fuzzer.generate_test_case(2)

    assert generated.test_id == "fuzz_0002"
    assert isinstance(generated.input_data, bytes)
    assert isinstance(generated.description, str)
