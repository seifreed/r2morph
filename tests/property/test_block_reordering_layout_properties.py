"""Property checks for fallthrough-safe block ordering."""

from hypothesis import given
from hypothesis import strategies as st

from r2morph.mutations.block_reordering_relocation import _BlockPlan, _draw_new_order
from tests._doubles.relocation_order_rng import ReverseShuffle
from tests.utils.assertions import expect


@given(chain_lengths=st.lists(st.integers(min_value=1, max_value=8), min_size=2, max_size=8))
def test_block_reordering_order_preserves_fallthrough_chains(chain_lengths: list[int]) -> None:
    blocks: list[dict[str, int]] = []
    plans: dict[int, _BlockPlan] = {}
    next_address = 0x1000
    for chain_length in chain_lengths:
        chain = [next_address + index * 4 for index in range(chain_length)]
        blocks.extend({"addr": address} for address in chain)
        for index, address in enumerate(chain):
            successor = chain[index + 1] if index + 1 < chain_length else None
            plans[address] = _BlockPlan(address, [], successor)
        next_address += chain_length * 4

    reordered = _draw_new_order(blocks, plans, ReverseShuffle())
    result = blocks if reordered is None else reordered
    result_addresses = [block["addr"] for block in result]
    result_positions = {address: index for index, address in enumerate(result_addresses)}
    original_addresses = [block["addr"] for block in blocks]

    expect(
        result_addresses[: chain_lengths[0]] == original_addresses[: chain_lengths[0]]
        and sorted(result_addresses) == original_addresses
        and all(
            result_positions[plan.fallthrough] == result_positions[address] + 1
            for address, plan in plans.items()
            if plan.fallthrough is not None
        )
    )
