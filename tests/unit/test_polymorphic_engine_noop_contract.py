from r2morph.mutations.polymorphic_engine_noop import NoOp, NoOpMutation
from tests.utils.assertions import expect


def test_noop_contracts_return_list_mutations():
    expect(NoOp().apply(None)["mutations"] == [])
    expect(not (NoOpMutation().apply(None)["applied"] is not False))
