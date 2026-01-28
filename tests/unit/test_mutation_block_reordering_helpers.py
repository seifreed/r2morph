import random

from r2morph.mutations.block_reordering import BlockReorderingPass


def test_block_reordering_helper_methods():
    pass_obj = BlockReorderingPass()

    # _can_reorder_function
    small_func = {"size": 10}
    large_blocks = [{"addr": i, "size": 4} for i in range(60)]
    assert pass_obj._can_reorder_function(small_func, [{"addr": 0, "size": 4}]) is False
    assert pass_obj._can_reorder_function({"size": 30}, [{"addr": 0, "size": 4}]) is False
    assert pass_obj._can_reorder_function({"size": 30}, large_blocks) is False
    assert pass_obj._can_reorder_function(
        {"size": 30},
        [{"addr": 0, "size": 8}, {"addr": 8, "size": 8}],
    ) is True

    # _generate_reordering preserves first block
    random.seed(42)
    blocks = [{"addr": 0}, {"addr": 1}, {"addr": 2}, {"addr": 3}]
    new_order = pass_obj._generate_reordering(blocks)
    assert new_order[0] == 0
    assert sorted(new_order) == [0, 1, 2, 3]

    # _calculate_jump_cost
    original = [0, 1, 2, 3]
    reordered = [0, 2, 1, 3]
    cost = pass_obj._calculate_jump_cost(original, reordered)
    assert cost >= 1
