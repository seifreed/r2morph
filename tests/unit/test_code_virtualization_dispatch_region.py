"""
The dispatch-region extraction contract for a computed jump.

``extract_region(..., allow_computed_jump=True)`` lowers a register-indirect jump to
an ``ijmp`` item and builds a target map (native address -> item index) so the ijmp
handler can re-enter the VM at the virtualized target. Callers can reject computed
jumps explicitly, and an ordinary region carries an empty target map.

These drive the pure extraction function with hand-built instruction dicts - no r2,
no mocks.
"""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_dispatch_lifting import complete_direct_branch_ops
from r2morph.mutations.code_virtualization_region import extract_region
from tests.utils.assertions import expect


def _insn(addr: int, size: int, itype: str, opcode: str, **extra: object) -> dict[str, object]:
    return {"addr": addr, "size": size, "type": itype, "opcode": opcode, **extra}


def _dispatch_instructions() -> list[dict[str, object]]:
    """Load a computed target into a register, jump through it, then return."""
    return [
        _insn(0x1000, 3, "mov", "mov rdx, qword [rax]"),
        _insn(0x1003, 2, "rjmp", "jmp rdx"),
        _insn(0x1005, 1, "ret", "ret"),
    ]


class _FakeR2:
    def __init__(self, responses: dict[int, list[dict[str, object]]]) -> None:
        self.responses = responses
        self.queries: list[int] = []

    def cmdj(self, command: str) -> list[dict[str, object]]:
        target = int(command.rsplit("@ ", 1)[1])
        self.queries.append(target)
        return self.responses.get(target, [])


class _FakeBinary:
    def __init__(self, responses: dict[int, list[dict[str, object]]]) -> None:
        self.r2 = _FakeR2(responses)


def test_complete_direct_branch_ops_reads_missing_in_range_targets() -> None:
    binary = _FakeBinary(
        {
            0x1010: [
                _insn(0x1010, 2, "mov", "mov eax, 1"),
                _insn(0x1012, 2, "jmp", "jmp 0x1018", jump=0x1018),
                _insn(0x1018, 1, "ret", "ret"),
            ]
        }
    )
    ops = [
        _insn(0x1000, 2, "cjmp", "je 0x1010", jump=0x1010),
        _insn(0x1002, 1, "ret", "ret"),
    ]

    completed = complete_direct_branch_ops(binary, ops, (0x1000, 0x1020))

    expect([op["addr"] for op in completed] == [0x1000, 0x1002, 0x1010, 0x1012, 0x1018])
    expect(binary.r2.queries == [0x1010, 0x1018])


def test_complete_direct_branch_ops_ignores_out_of_range_targets() -> None:
    binary = _FakeBinary({0x2000: [_insn(0x2000, 1, "ret", "ret")]})
    ops = [_insn(0x1000, 2, "jmp", "jmp 0x2000", jump=0x2000)]

    completed = complete_direct_branch_ops(binary, ops, (0x1000, 0x1010))

    expect([op["addr"] for op in completed] == [0x1000])
    expect(binary.r2.queries == [])


def test_dispatch_region_lowers_computed_jump_to_ijmp() -> None:
    """With the contract enabled, the register-indirect jump becomes an ijmp item."""
    region = extract_region(_dispatch_instructions(), randomness.Random(1), allow_computed_jump=True)
    expect(region is not None)
    expect(any(item[0] == "ijmp" for item in region.instructions))


def test_dispatch_region_builds_target_map_over_body_addresses() -> None:
    """The target map covers the body instruction addresses a computed jump may hit."""
    region = extract_region(_dispatch_instructions(), randomness.Random(1), allow_computed_jump=True)
    expect(region is not None)
    expect(set(region.target_map) == {4096, 4099})


def test_computed_jump_rejected_without_opt_in() -> None:
    """The default straight-line contract still rejects a computed jump."""
    expect(not (extract_region(_dispatch_instructions(), randomness.Random(1)) is not None))


def test_ordinary_region_has_empty_target_map() -> None:
    """A region with no computed jump carries no target map, even when opted in."""
    insns = [_insn(0x1000, 3, "add", "add eax, ebx"), _insn(0x1003, 1, "ret", "ret")]
    region = extract_region(insns, randomness.Random(1), allow_computed_jump=True)
    expect(region is not None)
    expect(region.target_map == {})
