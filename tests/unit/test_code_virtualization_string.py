"""Unit contracts for implicit-memory string instruction lowering."""

from __future__ import annotations

import pytest

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_models import _op_key
from r2morph.mutations.code_virtualization_region_string import direction_control_handler_asm, string_handler_asm
from tests.utils.assertions import expect


def test_classify_rep_movsb_returns_string_item() -> None:
    item = _classify({"type": "movs", "opcode": "rep movsb"})
    expect(item == ["string", "movs", 8, "rep"])


def test_classify_direction_control_returns_virtual_flag_item() -> None:
    expect(_classify({"type": "other", "opcode": "cld"}) == ["cld"])


def test_classify_vector_movsd_does_not_become_string_item() -> None:
    item = _classify({"type": "mov", "opcode": "movsd xmm0, xmm1"})
    expect(item is not None and item[0] != "string")


def test_string_item_has_stable_handler_key() -> None:
    expect(_op_key(("string", "cmps", 32, "repe")) == "string_cmps_32_repe")


def test_string_handler_updates_guest_implicit_registers_and_flags() -> None:
    assembly = string_handler_asm("string_movs_64_rep", tuple(range(16)), 0x90)
    expect(
        "rep movsq" in assembly
        and "mov rsi, qword ptr [rsp+48]" in assembly
        and "mov rdi, qword ptr [rsp+56]" in assembly
        and "mov rcx, qword ptr [rsp+8]" in assembly
        and "push qword ptr [rsp+144]" in assembly
    )


def test_string_handler_rejects_unknown_width() -> None:
    with pytest.raises(ValueError, match="unsupported string width"):
        string_handler_asm("string_movs_128_rep", tuple(range(16)), 0x90)


def test_direction_control_handler_updates_virtual_flags() -> None:
    assembly = direction_control_handler_asm("std", 0x90)
    expect("or r10, 1024" in assembly and "mov qword ptr [rsp+144], r10" in assembly)
