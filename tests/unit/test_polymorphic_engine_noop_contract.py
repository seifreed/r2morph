from r2morph.mutations.polymorphic_engine_noop import NoOp, NoOpMutation


def test_noop_contracts_return_list_mutations():
    assert NoOp().apply(None)["mutations"] == []
    assert NoOpMutation().apply(None)["applied"] is False
