from __future__ import annotations

from r2morph.mutations.code_mobility_models import (
    MobileBlock,
    MobilityPlan,
    calculate_section_offsets,
    estimate_size_with_jumps,
)
from tests.utils.assertions import expect

_EXPECTED_BLOCK_GET_JUMP_SIZE_5 = 5


def test_code_mobility_models_cover_the_core_paths() -> None:
    block = MobileBlock(
        block_id=1,
        original_address=0x1000,
        original_section=".text",
        size=32,
        target_section=".mobile_0",
    )

    plan = MobilityPlan()
    plan.add_block(block)

    expect(block.get_jump_size() == _EXPECTED_BLOCK_GET_JUMP_SIZE_5)
    expect(plan.blocks[0].block_id == 1)
    expect(not (calculate_section_offsets([".mobile_0", ".mobile_1"])[".mobile_1"] <= 0))
    expect(not (estimate_size_with_jumps([block]) <= block.size))
