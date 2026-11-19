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

from types import SimpleNamespace
from typing import Any

from r2morph.core import randomness
from r2morph.mutations import code_virtualization_dispatch_lifting as dispatch_lifting
from r2morph.mutations.code_virtualization_dispatch_lifting import complete_direct_branch_ops, gather_dispatch_ops
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

    def cmdj(self, command: str) -> Any:
        if command == "iHj":
            return {"header": ""}
        if command == "iej":
            return []
        target = int(command.rsplit("@ ", 1)[1])
        self.queries.append(target)
        return self.responses.get(target, [])


class _FakeBinary:
    def __init__(
        self, responses: dict[int, list[dict[str, object]]], functions: list[dict[str, object]] | None = None
    ) -> None:
        self.r2 = _FakeR2(responses)
        self.functions = functions or []

    def get_sections(self) -> list[dict[str, object]]:
        return [{"perm": "r-x", "vaddr": 0x1000, "vsize": 0x100}]

    def get_functions(self) -> list[dict[str, object]]:
        return self.functions


def test_complete_direct_branch_ops_reads_missing_in_range_targets() -> None:
    binary = _FakeBinary(
        {
            0x1010: [
                _insn(0x1010, 2, "mov", "mov eax, 1"),
                _insn(0x1012, 2, "jmp", "jmp 0x1018", jump=0x1018),
            ],
            0x1018: [_insn(0x1018, 1, "ret", "ret")],
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


def test_complete_direct_branch_ops_stops_probe_after_unconditional_jump() -> None:
    binary = _FakeBinary(
        {
            0x1010: [
                _insn(0x1010, 2, "mov", "mov eax, 1"),
                _insn(0x1012, 2, "jmp", "jmp 0x1018", jump=0x1018),
                _insn(0x1014, 1, "mov", "mov eax, 2"),
            ],
        }
    )
    ops = [_insn(0x1000, 2, "cjmp", "je 0x1010", jump=0x1010), _insn(0x1002, 1, "ret", "ret")]

    completed = complete_direct_branch_ops(binary, ops, (0x1000, 0x1020))

    expect([op["addr"] for op in completed] == [0x1000, 0x1002, 0x1010, 0x1012])


def test_gather_dispatch_ops_includes_resolved_in_function_switch_targets(monkeypatch) -> None:
    class _SwitchTableAnalyzer:
        def __init__(self, _binary: object) -> None:
            pass

        def detect_switch_pattern(self, _function_start: int) -> tuple[list[object], list[object]]:
            table = SimpleNamespace(
                entries=[SimpleNamespace(target_address=0x1010), SimpleNamespace(target_address=0x1020)]
            )
            return [table], []

    monkeypatch.setattr(dispatch_lifting, "SwitchTableAnalyzer", _SwitchTableAnalyzer)
    binary = _FakeBinary(
        {
            0x1000: [
                _insn(0x1000, 7, "ujmp", "jmp qword [rcx*8 + 0x2000]"),
                _insn(0x1007, 1, "ret", "ret"),
            ],
            0x1010: [_insn(0x1010, 2, "mov", "mov eax, 1"), _insn(0x1012, 1, "ret", "ret")],
            0x1020: [_insn(0x1020, 2, "mov", "mov eax, 2"), _insn(0x1022, 1, "ret", "ret")],
        },
        functions=[{"offset": 0x1000}, {"offset": 0x1010}, {"offset": 0x1020}, {"offset": 0x1080}],
    )

    ops = gather_dispatch_ops(binary, {"addr": 0x1000, "size": 0x10})

    expect(ops is not None and [op["addr"] for op in ops] == [0x1000, 0x1007, 0x1010, 0x1012, 0x1020, 0x1022])


def test_gather_dispatch_ops_stops_at_next_function_start(monkeypatch) -> None:
    class _SwitchTableAnalyzer:
        def __init__(self, _binary: object) -> None:
            pass

        def detect_switch_pattern(self, _function_start: int) -> tuple[list[object], list[object]]:
            return [SimpleNamespace(entries=[SimpleNamespace(target_address=0x1010)])], []

    monkeypatch.setattr(dispatch_lifting, "SwitchTableAnalyzer", _SwitchTableAnalyzer)
    binary = _FakeBinary(
        {
            0x1000: [_insn(0x1000, 7, "ujmp", "jmp qword [rcx*8 + 0x2000]"), _insn(0x1007, 1, "ret", "ret")],
            0x1010: [
                _insn(0x1010, 2, "mov", "mov eax, 1"),
                _insn(0x1012, 2, "jmp", "jmp 0x1080", jump=0x1080),
                _insn(0x1014, 1, "ret", "ret"),
            ],
            0x1080: [_insn(0x1080, 1, "ret", "ret")],
        },
        functions=[{"offset": 0x1000}, {"offset": 0x1080}],
    )

    ops = gather_dispatch_ops(binary, {"addr": 0x1000, "size": 0x10})

    expect(ops is not None and [op["addr"] for op in ops] == [0x1000, 0x1007, 0x1010, 0x1012])


def test_gather_dispatch_ops_excludes_switch_targets_outside_function(monkeypatch) -> None:
    class _SwitchTableAnalyzer:
        def __init__(self, _binary: object) -> None:
            pass

        def detect_switch_pattern(self, _function_start: int) -> tuple[list[object], list[object]]:
            table = SimpleNamespace(entries=[SimpleNamespace(target_address=0x2000)])
            return [table], []

    monkeypatch.setattr(dispatch_lifting, "SwitchTableAnalyzer", _SwitchTableAnalyzer)
    binary = _FakeBinary(
        {
            0x1000: [
                _insn(0x1000, 7, "ujmp", "jmp qword [rcx*8 + 0x2000]"),
                _insn(0x1007, 1, "ret", "ret"),
            ],
            0x2000: [_insn(0x2000, 1, "ret", "ret")],
        }
    )

    ops = gather_dispatch_ops(binary, {"addr": 0x1000, "size": 0x40})

    expect(ops is not None and [op["addr"] for op in ops] == [0x1000, 0x1007])


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
