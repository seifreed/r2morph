from r2morph.mutations.block_reordering import BlockReorderingPass


def test_block_reordering_edge_cases():
    pass_obj = BlockReorderingPass()

    # No blocks
    assert pass_obj._generate_reordering([]) == []

    # Single block
    assert pass_obj._generate_reordering([{"addr": 0}]) == [0]

    # Jump cost trivial
    assert pass_obj._calculate_jump_cost([0], [0]) == 0
