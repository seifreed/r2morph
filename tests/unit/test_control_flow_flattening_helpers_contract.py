from r2morph.mutations.control_flow_flattening_helpers import (
    assemble_bounded,
    candidate_block_count,
    find_nop_sequences,
    is_conditional_jump,
    select_candidates,
)
from tests.utils.assertions import expect

_EXPECTED_CANDIDATE_BLOCK_COUNT_BINARY_FUNCTIONS_0_2_3 = 3
_EXPECTED_SELECT_CANDIDATES_BINARY_FUNCTIONS_2_0_BLOCK__3 = 3


class _Binary:
    def __init__(self) -> None:
        self._blocks = {
            0x1000: [object(), object(), object()],
            0x2000: [object()],
        }

    def get_basic_blocks(self, addr: int):
        return self._blocks[addr]

    def assemble(self, insn: str):
        table = {"nop": b"\x90", "ret": b"\xc3"}
        return table.get(insn)


def test_control_flow_flattening_leaf_helpers_cover_the_core_paths() -> None:
    binary = _Binary()
    functions = [
        {"name": "main", "offset": 0x1000, "size": 64},
        {"name": "sym.imp.memcpy", "offset": 0x2000, "size": 64},
    ]

    expect(not (is_conditional_jump("je", "x86") is not True))
    expect(not (is_conditional_jump("jmp", "x86") is not False))
    expect(candidate_block_count(binary, functions[0], 2) == _EXPECTED_CANDIDATE_BLOCK_COUNT_BINARY_FUNCTIONS_0_2_3)
    expect(not (candidate_block_count(binary, functions[1], 2) is not None))
    expect(
        select_candidates(binary, functions, 2)[0]["_block_count"]
        == _EXPECTED_SELECT_CANDIDATES_BINARY_FUNCTIONS_2_0_BLOCK__3
    )
    expect(
        find_nop_sequences(
            [
                {"opcode": "nop", "offset": 16, "size": 1},
                {"opcode": "nop", "offset": 17, "size": 2},
                {"opcode": "ret", "offset": 19, "size": 1},
            ]
        )
        == [(16, 3)]
    )
    expect(assemble_bounded(binary, ["nop", "ret"], 2) == b"\x90\xc3")
    expect(not (assemble_bounded(binary, ["nop", "ret"], 1) is not None))
