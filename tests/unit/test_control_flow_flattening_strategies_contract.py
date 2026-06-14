"""Contract tests for control-flow flattening strategies."""

from __future__ import annotations

from r2morph.mutations.cff_opaque_predicates import OpaquePredicateGenerator
from r2morph.mutations.control_flow_flattening_strategies import apply_block_strategies


class _FakeBinary:
    def __init__(self) -> None:
        self.writes: list[tuple[int, bytes]] = []

    def assemble(self, insn: str) -> bytes:
        if insn == "cmp eax, eax":
            return b"\x39\xc0"
        if insn == "test eax, eax":
            return b"\x85\xc0"
        if insn == "nop":
            return b"\x90"
        return None

    def write_bytes(self, addr: int, data: bytes) -> bool:
        self.writes.append((addr, data))
        return True


class _FakeJumpObfuscator:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def obfuscate_jump(self, binary, last_insn, block, arch_family, bits) -> bool:  # noqa: ANN001
        self.calls.append((arch_family, bits))
        return True


class _FakePredicateGenerator(OpaquePredicateGenerator):
    def get_x86(self, bits: int) -> list[list[str]]:  # noqa: D401
        return [["nop"]]

    def get_arm(self, bits: int) -> list[list[str]]:  # noqa: D401
        return [["nop"]]


def test_apply_block_strategies_mutates_counts_and_writes() -> None:
    binary = _FakeBinary()
    predicate_generator = _FakePredicateGenerator()
    jump_obfuscator = _FakeJumpObfuscator()
    blocks = [
        {"addr": 0x1000, "size": 6},
        {"addr": 0x2000, "size": 6},
        {"addr": 0x3000, "size": 6},
    ]
    all_instrs = [
        {"offset": 0x1000, "size": 1, "mnemonic": "mov"},
        {"offset": 0x1003, "size": 1, "mnemonic": "je"},
        {"offset": 0x2000, "size": 2, "mnemonic": "jmp"},
        {"offset": 0x3000, "size": 1, "mnemonic": "nop"},
    ]
    mutations = {"opaque_predicates": 0, "jump_obfuscations": 0, "total": 0}

    added = apply_block_strategies(
        binary,
        blocks,
        all_instrs,
        "x86",
        64,
        2,
        mutations,
        predicate_generator,
        jump_obfuscator,
    )

    assert added == 1
    assert mutations["opaque_predicates"] == 1
    assert mutations["jump_obfuscations"] == 1
    assert mutations["total"] == 2
    assert binary.writes
    assert jump_obfuscator.calls == [("x86", 64)]
