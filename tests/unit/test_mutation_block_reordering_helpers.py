from r2morph.core import randomness
from r2morph.mutations.block_reordering import BlockReorderingPass
from tests.utils.assertions import expect


def test_block_reordering_helper_methods():
    pass_obj = BlockReorderingPass()

    # _can_reorder_function
    small_func = {"size": 10}
    large_blocks = [{"addr": i, "size": 4} for i in range(60)]
    expect(not (pass_obj._can_reorder_function(small_func, [{"addr": 0, "size": 4}]) is not False))
    expect(not (pass_obj._can_reorder_function({"size": 30}, [{"addr": 0, "size": 4}]) is not False))
    expect(not (pass_obj._can_reorder_function({"size": 30}, large_blocks) is not False))
    expect(
        not (
            pass_obj._can_reorder_function(
                {"size": 30},
                [{"addr": 0, "size": 8}, {"addr": 8, "size": 8}],
            )
            is not True
        )
    )

    # _generate_reordering preserves first block
    randomness.seed(42)
    blocks = [{"addr": 0}, {"addr": 1}, {"addr": 2}, {"addr": 3}]
    new_order = pass_obj._generate_reordering(blocks)
    expect(new_order[0] == 0)
    expect(sorted(new_order) == [0, 1, 2, 3])

    # _calculate_jump_cost
    original = [0, 1, 2, 3]
    reordered = [0, 2, 1, 3]
    cost = pass_obj._calculate_jump_cost(original, reordered)
    expect(not (cost < 1))
