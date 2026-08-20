from r2morph.mutations.block_reordering import BlockReorderingPass
from tests.utils.assertions import expect


def test_block_reordering_edge_cases():
    pass_obj = BlockReorderingPass()

    # No blocks
    expect(pass_obj._generate_reordering([]) == [])

    # Single block
    expect(pass_obj._generate_reordering([{"addr": 0}]) == [0])

    # Jump cost trivial
    expect(pass_obj._calculate_jump_cost([0], [0]) == 0)
