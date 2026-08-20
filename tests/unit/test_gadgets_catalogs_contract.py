"""Contracts for gadget catalog helpers."""

from r2morph.analysis.os_flags import OSFlags
from r2morph.mutations.gadgets_catalogs import build_jump_gadgets, build_operate_gadgets, build_stack_gadgets
from tests.utils.assertions import expect


def test_stack_and_jump_catalogs_have_expected_entries() -> None:
    stack = build_stack_gadgets()
    jump = build_jump_gadgets()

    expect(not ({"push_reg", "sub_mov"} > set(stack)))
    expect(not ({"jz", "jnz", "jg", "jle"} > set(jump)))
    expect(stack["push_reg"][0]("rax") == "push rax")
    expect(jump["jz"][0]("L1") == "jz L1")


def test_operate_catalog_includes_static_families() -> None:
    gadgets = build_operate_gadgets(OSFlags("linux"), stack_depth=4)

    expect(not ("mov_reg_reg" not in gadgets))
    expect(not ("lea_reg_rsp" not in gadgets))
    expect(not ("xor_reg_imm" not in gadgets))
    expect(gadgets["mov_reg_rsp"][0]("rax", "rbx") == "mov rax, rsp")
    expect(gadgets["nop"][0]("rax", "rbx") == "nop")
