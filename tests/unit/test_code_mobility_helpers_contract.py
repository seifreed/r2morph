from __future__ import annotations

import r2morph.mutations.code_mobility_helpers as mobility_helpers
from r2morph.mutations.code_mobility_models import MobileBlock


def test_code_mobility_helpers_cover_the_core_paths(monkeypatch) -> None:
    block = {"size": 8, "type": "code"}
    assert mobility_helpers.can_move_block(block) == (True, "")
    assert mobility_helpers.select_target_section(3, 4, ".mobile") == ".mobile_3"

    mobile_block = MobileBlock(
        block_id=1,
        original_address=0x1000,
        original_section=".text",
        size=32,
        successors=[0x2000],
    )
    generated = mobility_helpers.generate_block_code(mobile_block, ".text")
    assert "block_0001" in generated
    assert "jmp block_2000" in generated

    assert "Trampoline" in mobility_helpers.generate_trampoline(0x2000, ".mobile_0")
    assert "Mobile section" in mobility_helpers.generate_section_header(".mobile_0", 0)

    monkeypatch.setattr(mobility_helpers.random, "shuffle", lambda seq: seq.reverse())
    blocks = [mobile_block, MobileBlock(2, 0x2000, ".text", 16)]
    assert mobility_helpers.interleave_blocks(blocks, preserve_order=True) == blocks
    shuffled = mobility_helpers.interleave_blocks(blocks, preserve_order=False, seed=42)
    assert shuffled[0].block_id == 2
