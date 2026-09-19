from __future__ import annotations

from r2morph.mutations import nop_insertion
from r2morph.mutations.nop_insertion import NopInsertionPass
from tests.utils.assertions import expect


class _Arm32Binary:
    def __init__(self) -> None:
        self.writes: list[tuple[int, bytes]] = []

    def assemble(self, instruction: str, _function_address: int) -> bytes | None:
        if instruction in {"nop", "mov r0, r0", "add r4, r4, #0"}:
            return b"\x00\x00\xa0\xe1"
        return None

    def read_bytes(self, _address: int, size: int) -> bytes:
        return b"\x01\x00\xa0\xe1"[:size]

    def write_bytes(self, address: int, data: bytes) -> bool:
        self.writes.append((address, data))
        return True


def test_arm32_nop_tries_next_assembly_candidate_after_failure() -> None:
    nop_insertion.random.seed(1)
    binary = _Arm32Binary()
    pass_instance = NopInsertionPass({"probability": 1.0})

    applied = pass_instance._apply_arm32_instruction(
        binary,
        {"addr": 0x1000},
        {"addr": 0x1000, "size": 4, "disasm": "nop"},
        ["invalid instruction", "mov r0, r0"],
    )

    expect(applied)
    expect(binary.writes == [(0x1000, b"\x00\x00\xa0\xe1")])


def test_arm32_nop_keeps_self_move_on_the_same_register() -> None:
    nop_insertion.random.seed(2)
    binary = _Arm32Binary()
    pass_instance = NopInsertionPass({"probability": 1.0})

    applied = pass_instance._apply_arm32_instruction(
        binary,
        {"addr": 0x1000},
        {"addr": 0x1000, "size": 4, "disasm": "mov r4, r4"},
        ["mov r0, r0"],
    )

    expect(applied)
    expect(binary.writes == [(0x1000, b"\x00\x00\xa0\xe1")])
    expect(pass_instance.get_records()[0].mutated_disasm == "nop")
