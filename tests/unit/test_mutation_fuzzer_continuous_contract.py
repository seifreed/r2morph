from r2morph.validation.mutation_fuzzer_continuous import ContinuousFuzzer, create_continuous_fuzzer
from r2morph.validation.mutation_fuzzer_types import FuzzConfig
from tests.utils.assertions import expect

_EXPECTED_CREATED_CONFIG_NUM_TESTS_3 = 3
_EXPECTED_CREATED_CONFIG_TIMEOUT_2 = 2
_EXPECTED_FUZZER_REGRESSION_THRESHOLD_0_95 = 0.95


def test_mutation_fuzzer_continuous_contract() -> None:
    fuzzer = ContinuousFuzzer(FuzzConfig(num_tests=1, timeout=1))

    expect(fuzzer.campaign_history == [])
    expect(fuzzer.regression_threshold == _EXPECTED_FUZZER_REGRESSION_THRESHOLD_0_95)

    created = create_continuous_fuzzer(num_tests=3, timeout=2)
    expect(isinstance(created, ContinuousFuzzer))
    expect(created.config.num_tests == _EXPECTED_CREATED_CONFIG_NUM_TESTS_3)
    expect(created.config.timeout == _EXPECTED_CREATED_CONFIG_TIMEOUT_2)
