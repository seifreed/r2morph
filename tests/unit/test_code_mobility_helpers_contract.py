from __future__ import annotations

import r2morph.mutations.code_mobility_helpers as mobility_helpers
from r2morph.mutations.code_mobility_models import MobileBlock
from tests.utils.assertions import expect

_EXPECTED_SHUFFLED_0_BLOCK_ID_2 = 2


def test_code_mobility_helpers_cover_the_core_paths() -> None:
    block = {"size": 8, "type": "code"}
    expect(mobility_helpers.can_move_block(block) == (True, ""))
    expect(mobility_helpers.select_target_section(3, 4, ".mobile") == ".mobile_3")

    mobile_block = MobileBlock(
        block_id=1,
        original_address=0x1000,
        original_section=".text",
        size=32,
        successors=[0x2000],
    )
    generated = mobility_helpers.generate_block_code(mobile_block, ".text")
    expect(not ("block_0001" not in generated))
    expect(not ("jmp block_2000" not in generated))

    expect(not ("Trampoline" not in mobility_helpers.generate_trampoline(0x2000, ".mobile_0")))
    expect(not ("Mobile section" not in mobility_helpers.generate_section_header(".mobile_0", 0)))

    blocks = [mobile_block, MobileBlock(2, 0x2000, ".text", 16)]
    expect(mobility_helpers.interleave_blocks(blocks, preserve_order=True) == blocks)
    shuffled = mobility_helpers.interleave_blocks(blocks, preserve_order=False, seed=42)
    expect(shuffled[0].block_id == _EXPECTED_SHUFFLED_0_BLOCK_ID_2)
