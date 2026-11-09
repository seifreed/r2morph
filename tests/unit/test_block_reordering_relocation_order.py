from r2morph.mutations.block_reordering_relocation import _BlockPlan, _draw_new_order
from tests._doubles.relocation_order_rng import ReverseShuffle
from tests.utils.assertions import expect


def _blocks() -> list[dict[str, int]]:
    return [{"addr": address} for address in (0x1000, 0x1010, 0x1020, 0x1030, 0x1040)]


def _plans(blocks: list[dict[str, int]]) -> dict[int, _BlockPlan]:
    addresses = [block["addr"] for block in blocks]
    return {
        address: _BlockPlan(address, [], addresses[index + 1] if index == 0 else None)
        for index, address in enumerate(addresses)
    }


def test_draw_new_order_keeps_fallthrough_chain_adjacent() -> None:
    blocks = _blocks()

    reordered = _draw_new_order(blocks, _plans(blocks), ReverseShuffle())

    expect(reordered is not None and [block["addr"] for block in reordered[:2]] == [0x1000, 0x1010])


def test_draw_new_order_shuffles_independent_groups() -> None:
    blocks = _blocks()

    reordered = _draw_new_order(blocks, _plans(blocks), ReverseShuffle())

    expect(reordered is not None and reordered[2:] != blocks[2:])


def test_draw_new_order_retains_every_block() -> None:
    blocks = _blocks()

    reordered = _draw_new_order(blocks, _plans(blocks), ReverseShuffle())

    expect(reordered is not None and {block["addr"] for block in reordered} == {block["addr"] for block in blocks})
