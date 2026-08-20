from __future__ import annotations

from r2morph.core import randomness
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
from tests.utils.assertions import expect


def test_input_helpers_return_bytes() -> None:
    config = FuzzConfig(num_tests=1, timeout=1, seed=1, min_input_size=4, max_input_size=8)

    randomness.seed(1)
    expect(isinstance(generate_random_input(config, 8), bytes))
    expect(isinstance(generate_ascii_input(config, 8), bytes))
    expect(isinstance(generate_binary_input(config, 8), bytes))
    expect(isinstance(generate_structured_input(config, 8), bytes))
    expect(isinstance(generate_edge_case_input(config, 8), bytes))
    expect(isinstance(generate_format_string_input(config, 8), bytes))
    expect(isinstance(generate_path_like_input(config, 8), bytes))


def test_generate_test_case_uses_expected_contract() -> None:
    config = FuzzConfig(num_tests=1, timeout=1, seed=7, min_input_size=4, max_input_size=8)

    randomness.seed(7)
    test_case = generate_test_case(config, 3)

    expect(test_case.test_id == "fuzz_0003")
    expect(isinstance(test_case.input_data, bytes))
    expect(isinstance(test_case.args, list))
    expect(isinstance(test_case.env, dict))


def test_mutation_pass_fuzzer_delegates_to_input_helpers() -> None:
    fuzzer = MutationPassFuzzer(FuzzConfig(seed=11, min_input_size=4, max_input_size=8))

    randomness.seed(11)
    generated = fuzzer.generate_test_case(2)

    expect(generated.test_id == "fuzz_0002")
    expect(isinstance(generated.input_data, bytes))
    expect(isinstance(generated.description, str))
