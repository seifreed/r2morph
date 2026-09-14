import capstone
import pytest

from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.mutations.block_reordering_relocation import _BailOutError, _classify_instructions
from tests.utils.assertions import expect


def test_block_reordering_edge_cases():
    pass_obj = BlockReorderingPass()

    # No blocks
    expect(pass_obj._generate_reordering([]) == [])

    # Single block
    expect(pass_obj._generate_reordering([{"addr": 0}]) == [0])

    # Jump cost trivial
    expect(pass_obj._calculate_jump_cost([0], [0]) == 0)


def test_block_reordering_rejects_absolute_rendered_rip_relative_operand() -> None:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instruction = {
        "addr": 0x40118D,
        "bytes": "f20f100d7b0e0000",
        "disasm": "movsd xmm1, qword [0x402010]",
        "type": "mov",
    }

    with pytest.raises(_BailOutError, match="RIP-relative"):
        _classify_instructions([instruction], decoder)
