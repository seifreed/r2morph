from __future__ import annotations

import r2morph.core.randomness as random
from r2morph.validation import fuzzer_inputs
from r2morph.validation.fuzzer import MutationFuzzer


def test_fuzzer_input_helper_is_reused_by_mutation_fuzzer() -> None:
    fuzzer = MutationFuzzer(num_tests=1, timeout=1)
    random.seed(42)
    expected = fuzzer_inputs.generate_fuzz_input("structured")
    random.seed(42)
    assert fuzzer._generate_input("structured") == expected
