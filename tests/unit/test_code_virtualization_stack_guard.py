"""
Unit tests for the region VM's stack-balance guard and frame relocation.

The guard (`_stack_balanced`) decides whether a region's virtual push/pop traffic
is safe to virtualize: every path must reach each terminator at its entry depth
and no pop may underflow. These tests exercise the guard directly on crafted item
graphs (no r2, no binary) — real calls into the real function, no mocks.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region import _stack_balanced, extract_region
from r2morph.mutations.code_virtualization_region_handlers import (
    _GUARD,
    _STACK_ARGUMENT_COPY_BYTES,
    stack_argument_copy_asm,
)
from tests.utils.assertions import expect

_EXPANDED_STACK_ARGUMENT_OFFSET = 928


def test_guard_is_sixteen_byte_aligned() -> None:
    # The relocation must preserve the program's 16-byte stack alignment.
    expect(_GUARD % 16 == 0)


def test_stack_argument_copy_is_bounded_and_relocated() -> None:
    assembly = stack_argument_copy_asm(0x400)
    expect(f"mov ecx, {_STACK_ARGUMENT_COPY_BYTES // 8}" in assembly)
    expect("rep movsq" in assembly and "lea rdi, [rsp - 1016]" in assembly)


def test_region_stack_argument_window_covers_direct_rsp_access() -> None:
    instructions = [
        {
            "addr": 0x1000,
            "size": 8,
            "type": "mov",
            "opcode": f"mov rax, qword ptr [rsp+{_EXPANDED_STACK_ARGUMENT_OFFSET}]",
        },
        {"addr": 0x1008, "size": 1, "type": "ret", "opcode": "ret"},
    ]
    region = extract_region(instructions)
    expect(region is not None and region.stack_argument_copy_bytes == _EXPANDED_STACK_ARGUMENT_OFFSET)


def test_stack_balanced_accepts_matched_push_pop() -> None:
    items = [["push", 0, 64], ["pop", 0, 64], ["exit", 0x1000]]
    expect(not (_stack_balanced(items) is not True))


def test_stack_balanced_rejects_push_without_pop() -> None:
    # Reaches the terminator at depth 1 — the VM would force-restore rsp wrongly.
    items = [["push", 0, 64], ["exit", 0x1000]]
    expect(not (_stack_balanced(items) is not False))


def test_stack_balanced_rejects_pop_underflow() -> None:
    items = [["pop", 0, 64], ["exit", 0x1000]]
    expect(not (_stack_balanced(items) is not False))


def test_stack_balanced_accepts_branch_with_equal_depth_on_both_paths() -> None:
    items = [
        ["push", 0, 64],  # 0: depth 0 -> 1
        ["jcc", "je", 3],  # 1: depth 1, succ 2 and 3
        ["nop"],  # 2: depth 1 -> 3
        ["pop", 0, 64],  # 3: depth 1 -> 0
        ["exit", 0x1000],  # 4: depth 0
    ]
    expect(not (_stack_balanced(items) is not True))


def test_stack_balanced_rejects_paths_that_disagree_on_depth() -> None:
    items = [
        ["jcc", "je", 2],  # 0: depth 0, succ 1 and 2
        ["push", 0, 64],  # 1: depth 0 -> 1, then falls to 2
        ["exit", 0x1000],  # 2: reached at depth 0 and depth 1 -> conflict
    ]
    expect(not (_stack_balanced(items) is not False))
