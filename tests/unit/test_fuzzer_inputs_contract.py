from __future__ import annotations

from r2morph.validation import fuzzer_inputs
from r2morph.validation.fuzzer import MutationFuzzer


def test_fuzzer_input_helper_is_reused_by_mutation_fuzzer(monkeypatch) -> None:
    monkeypatch.setattr(fuzzer_inputs, "generate_fuzz_input", lambda input_type: f"generated:{input_type}")

    fuzzer = MutationFuzzer(num_tests=1, timeout=1)
    assert fuzzer._generate_input("structured") == "generated:structured"
