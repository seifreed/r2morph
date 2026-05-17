"""Characterization of SymbolicValidator._check_observables.

Pins the exact current contract (which observables get recorded, the
region_report mutations, and the mismatch payload shape) before the
BinaryRegionComparator extraction (clean-arch slice 3a).

No mocks / monkeypatch (CLAUDE.md §4). The angr collaborators are
modelled by small real classes: the solver faithfully reports a
constraint `left != right` as satisfiable iff the two values actually
differ (exactly angr's semantics for these concrete comparisons), and
memory actions use the same shape _collect_memory_write_signatures
already consumes. _check_observables is exercised on a real
SymbolicValidator so its real _collect_memory_write_signatures runs.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from r2morph.validation.symbolic_validator import SymbolicValidator


class _Regs:
    def __init__(self, **regs: Any) -> None:
        for name, value in regs.items():
            setattr(self, name, value)


class _Solver:
    @staticmethod
    def satisfiable(extra_constraints: list[Any]) -> bool:
        # extra_constraints == [left != right]; for concrete ints this is
        # a bool that is True exactly when the values differ — the same
        # outcome angr's solver would report for these snippets.
        return bool(extra_constraints[0])


class _State:
    def __init__(self, addr: Any, regs: _Regs, history: Any = None) -> None:
        self.addr = addr
        self.regs = regs
        self.solver = _Solver()
        self.history = history


def _mem_write(addr: int, size: int) -> SimpleNamespace:
    return SimpleNamespace(
        type="mem",
        action="write",
        addr=SimpleNamespace(concrete_value=addr),
        size=SimpleNamespace(concrete_value=size),
    )


def _history(actions: list[Any]) -> SimpleNamespace:
    return SimpleNamespace(actions=actions)


_MUTATION = {"start_address": 0x401000, "end_address": 0x401004}


def _run(
    original: _State,
    mutated: _State,
    *,
    compared_registers: list[str],
    stack_reg: str = "rsp",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    region_report: dict[str, Any] = {"mismatches": []}
    mismatches: list[dict[str, Any]] = []
    SymbolicValidator()._check_observables(
        region_report,
        mismatches,
        _MUTATION,
        original,
        mutated,
        compared_registers,
        stack_reg,
    )
    return region_report, mismatches


def test_all_observables_match_records_nothing_and_sets_memory_keys() -> None:
    regs_a = _Regs(rax=1, rsp=0x7000)
    regs_b = _Regs(rax=1, rsp=0x7000)
    region_report, mismatches = _run(_State(0x401000, regs_a), _State(0x401000, regs_b), compared_registers=["rax"])
    assert region_report["mismatches"] == []
    assert mismatches == []
    assert region_report["original_memory_writes"] == []
    assert region_report["mutated_memory_writes"] == []
    assert region_report["original_memory_write_count"] == 0
    assert region_report["mutated_memory_write_count"] == 0


def test_successor_address_mismatch_recorded() -> None:
    regs = dict(rax=1, rsp=0x7000)
    region_report, mismatches = _run(
        _State(0x401000, _Regs(**regs)),
        _State(0x402000, _Regs(**regs)),
        compared_registers=["rax"],
    )
    assert region_report["mismatches"] == ["successor_address"]
    assert mismatches == [{"start_address": 0x401000, "end_address": 0x401004, "observable": "successor_address"}]


def test_register_mismatch_only_for_differing_register() -> None:
    region_report, mismatches = _run(
        _State(0x401000, _Regs(rax=1, rbx=5, rsp=0x7000)),
        _State(0x401000, _Regs(rax=1, rbx=9, rsp=0x7000)),
        compared_registers=["rax", "rbx"],
    )
    assert region_report["mismatches"] == ["rbx"]
    assert mismatches[0]["observable"] == "rbx"


def test_register_skipped_when_attribute_missing_on_either_side() -> None:
    region_report, mismatches = _run(
        _State(0x401000, _Regs(rax=1, rsp=0x7000)),
        _State(0x401000, _Regs(rax=2, rsp=0x7000)),
        compared_registers=["rax", "rcx"],
    )
    # rcx absent on both -> skipped (no crash); rax differs -> recorded
    assert region_report["mismatches"] == ["rax"]


def test_eflags_mismatch_recorded_when_both_present() -> None:
    region_report, _ = _run(
        _State(0x401000, _Regs(rax=1, rsp=0x7000, eflags=0x202)),
        _State(0x401000, _Regs(rax=1, rsp=0x7000, eflags=0x246)),
        compared_registers=["rax"],
    )
    assert region_report["mismatches"] == ["eflags"]


def test_eflags_skipped_when_missing_on_one_side() -> None:
    region_report, _ = _run(
        _State(0x401000, _Regs(rax=1, rsp=0x7000, eflags=0x202)),
        _State(0x401000, _Regs(rax=1, rsp=0x7000)),
        compared_registers=["rax"],
    )
    assert region_report["mismatches"] == []


def test_stack_delta_mismatch_recorded() -> None:
    region_report, _ = _run(
        _State(0x401000, _Regs(rax=1, rsp=0x7000)),
        _State(0x401000, _Regs(rax=1, rsp=0x7008)),
        compared_registers=["rax"],
    )
    assert region_report["mismatches"] == ["stack_delta"]


def test_memory_writes_mismatch_recorded_and_signatures_exposed() -> None:
    original = _State(
        0x401000,
        _Regs(rax=1, rsp=0x7000),
        history=_history([_mem_write(0x1000, 8)]),
    )
    mutated = _State(0x401000, _Regs(rax=1, rsp=0x7000))
    region_report, mismatches = _run(original, mutated, compared_registers=["rax"])
    assert region_report["mismatches"] == ["memory_writes"]
    assert region_report["original_memory_writes"] == ["0x1000:8"]
    assert region_report["mutated_memory_writes"] == []
    assert region_report["original_memory_write_count"] == 1
    assert region_report["mutated_memory_write_count"] == 0
    assert mismatches[-1]["observable"] == "memory_writes"


def test_recording_order_is_successor_registers_eflags_stack_memory() -> None:
    original = _State(
        0x401000,
        _Regs(rax=1, rbx=5, rsp=0x7000, eflags=0x202),
        history=_history([_mem_write(0x1000, 8)]),
    )
    mutated = _State(
        0x402000,
        _Regs(rax=1, rbx=9, rsp=0x7008, eflags=0x246),
    )
    region_report, mismatches = _run(original, mutated, compared_registers=["rax", "rbx"])
    assert region_report["mismatches"] == [
        "successor_address",
        "rbx",
        "eflags",
        "stack_delta",
        "memory_writes",
    ]
    assert [m["observable"] for m in mismatches] == region_report["mismatches"]
    assert all(m["start_address"] == 0x401000 and m["end_address"] == 0x401004 for m in mismatches)
