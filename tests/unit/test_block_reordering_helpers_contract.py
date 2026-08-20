from r2morph.mutations.block_reordering_helpers import (
    calculate_jump_cost,
    can_reorder_function,
    generate_reordering,
    should_consider_function,
)
from tests.utils.assertions import expect


def test_block_reordering_helpers_cover_core_paths() -> None:
    func = {"size": 30}
    blocks = [{"addr": 0x1000}, {"addr": 0x1010}, {"addr": 0x1020}]

    expect(not (can_reorder_function(func, blocks) is not True))
    expect(not (should_consider_function(func, blocks) is not True))

    order = generate_reordering(blocks)
    expect(order[0] == 0)
    expect(sorted(order) == [0, 1, 2])

    expect(not (calculate_jump_cost([0, 1, 2], [0, 2, 1]) < 1))
