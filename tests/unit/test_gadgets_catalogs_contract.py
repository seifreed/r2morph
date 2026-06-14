"""Contracts for gadget catalog helpers."""

from r2morph.analysis.os_flags import OSFlags
from r2morph.mutations.gadgets_catalogs import build_jump_gadgets, build_operate_gadgets, build_stack_gadgets


def test_stack_and_jump_catalogs_have_expected_entries() -> None:
    stack = build_stack_gadgets()
    jump = build_jump_gadgets()

    assert {"push_reg", "sub_mov"} <= set(stack)
    assert {"jz", "jnz", "jg", "jle"} <= set(jump)
    assert stack["push_reg"][0]("rax") == "push rax"
    assert jump["jz"][0]("L1") == "jz L1"


def test_operate_catalog_includes_static_families() -> None:
    gadgets = build_operate_gadgets(OSFlags("linux"), stack_depth=4)

    assert "mov_reg_reg" in gadgets
    assert "lea_reg_rsp" in gadgets
    assert "xor_reg_imm" in gadgets
    assert gadgets["mov_reg_rsp"][0]("rax", "rbx") == "mov rax, rsp"
    assert gadgets["nop"][0]("rax", "rbx") == "nop"
