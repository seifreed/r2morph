import pytest

from r2morph.validation.regression import RegressionTester


def test_get_mutation_pass_mapping_and_errors():
    tester = RegressionTester()

    for name in ["nop", "substitute", "register", "expand", "reorder"]:
        mutation = tester._get_mutation_pass(name)
        assert mutation is not None

    with pytest.raises(ValueError):
        tester._get_mutation_pass("unknown-pass")
