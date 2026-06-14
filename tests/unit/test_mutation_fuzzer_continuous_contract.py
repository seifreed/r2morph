from r2morph.validation.mutation_fuzzer_continuous import ContinuousFuzzer, create_continuous_fuzzer
from r2morph.validation.mutation_fuzzer_types import FuzzConfig


def test_mutation_fuzzer_continuous_contract() -> None:
    fuzzer = ContinuousFuzzer(FuzzConfig(num_tests=1, timeout=1))

    assert fuzzer.campaign_history == []
    assert fuzzer.regression_threshold == 0.95

    created = create_continuous_fuzzer(num_tests=3, timeout=2)
    assert isinstance(created, ContinuousFuzzer)
    assert created.config.num_tests == 3
    assert created.config.timeout == 2
