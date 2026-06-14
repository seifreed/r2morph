from types import SimpleNamespace

from r2morph.validation.binary_region_comparator_observables import (
    check_observables,
    compare_register_states,
    compare_stack_and_memory,
)


class _ComparableValue:
    def __init__(self, value: int) -> None:
        self.value = value

    def __ne__(self, other: object) -> bool:  # pragma: no cover - exercised indirectly
        return isinstance(other, _ComparableValue) and self.value != other.value


class _FakeSolver:
    def satisfiable(self, extra_constraints: list[bool]) -> bool:
        return bool(extra_constraints and extra_constraints[0])


def _make_state(
    *,
    rax: int = 1,
    rbx: int = 2,
    eflags: int = 3,
    sp: int = 0x1000,
    addr: int = 0x5000,
    writes: list[tuple[int, int]] | None = None,
) -> SimpleNamespace:
    regs = SimpleNamespace(
        rax=_ComparableValue(rax),
        rbx=_ComparableValue(rbx),
        eflags=_ComparableValue(eflags),
        sp=_ComparableValue(sp),
    )
    history = SimpleNamespace(
        actions=[
            SimpleNamespace(type="mem", action="write", addr=addr, size=size)
            for addr, size in (writes or [])
        ]
    )
    return SimpleNamespace(regs=regs, solver=_FakeSolver(), history=history, addr=addr)


def test_compare_register_states_records_differences() -> None:
    original = _make_state(rax=1, rbx=2, eflags=3)
    mutated = _make_state(rax=9, rbx=2, eflags=7)
    seen: list[str] = []

    compare_register_states(original, mutated, ["rax", "rbx"], seen.append)

    assert seen == ["rax", "eflags"]


def test_compare_stack_and_memory_records_stack_and_write_changes() -> None:
    original = _make_state(sp=0x1000, writes=[(0x2000, 4)])
    mutated = _make_state(sp=0x2000, writes=[(0x3000, 8)])
    region_report: dict[str, object] = {}
    seen: list[str] = []

    compare_stack_and_memory(original, mutated, "sp", region_report, seen.append)

    assert seen == ["stack_delta", "memory_writes"]
    assert region_report == {
        "original_memory_writes": ["0x2000:4"],
        "mutated_memory_writes": ["0x3000:8"],
        "original_memory_write_count": 1,
        "mutated_memory_write_count": 1,
    }


def test_check_observables_populates_report_and_mismatches() -> None:
    original = _make_state(rax=1, writes=[(0x2000, 4)])
    mutated = _make_state(rax=9, addr=0x6000, writes=[(0x3000, 8)])
    region_report = {"mismatches": []}
    mismatches: list[dict[str, object]] = []

    check_observables(
        region_report,
        mismatches,
        {"start_address": 0x1000, "end_address": 0x1004},
        original,
        mutated,
        ["rax"],
        "sp",
    )

    assert region_report["mismatches"] == ["successor_address", "rax", "memory_writes"]
    assert mismatches == [
        {"start_address": 0x1000, "end_address": 0x1004, "observable": "successor_address"},
        {"start_address": 0x1000, "end_address": 0x1004, "observable": "rax"},
        {"start_address": 0x1000, "end_address": 0x1004, "observable": "memory_writes"},
    ]
