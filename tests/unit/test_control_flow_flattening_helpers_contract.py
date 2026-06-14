from r2morph.mutations.control_flow_flattening_helpers import (
    assemble_bounded,
    candidate_block_count,
    find_nop_sequences,
    is_conditional_jump,
    select_candidates,
)


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

    assert is_conditional_jump("je", "x86") is True
    assert is_conditional_jump("jmp", "x86") is False
    assert candidate_block_count(binary, functions[0], 2) == 3
    assert candidate_block_count(binary, functions[1], 2) is None
    assert select_candidates(binary, functions, 2)[0]["_block_count"] == 3
    assert find_nop_sequences([
        {"mnemonic": "nop", "offset": 0x10, "size": 1},
        {"mnemonic": "nop", "offset": 0x11, "size": 2},
        {"mnemonic": "ret", "offset": 0x13, "size": 1},
    ]) == [(0x10, 3)]
    assert assemble_bounded(binary, ["nop", "ret"], 2) == b"\x90\xc3"
    assert assemble_bounded(binary, ["nop", "ret"], 1) is None
