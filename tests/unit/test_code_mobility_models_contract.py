from __future__ import annotations

from r2morph.mutations.code_mobility_models import (
    MobileBlock,
    MobilityPlan,
    calculate_section_offsets,
    estimate_size_with_jumps,
)


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

    assert block.get_jump_size() == 5
    assert plan.blocks[0].block_id == 1
    assert calculate_section_offsets([".mobile_0", ".mobile_1"])[".mobile_1"] > 0
    assert estimate_size_with_jumps([block]) > block.size
