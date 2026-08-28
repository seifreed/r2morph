"""Contracts for x86 rotates through the virtual carry flag."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_decoders import _decode_shift, _decode_shift_reg
from r2morph.mutations.code_virtualization_region_microops import _vshift_handler_asm
from tests.utils.assertions import expect


def test_decode_immediate_carry_rotate_returns_rcl_item() -> None:
    expect(_decode_shift("rcl eax, 1") == ("rcl", 0, 1, 32))


def test_decode_variable_carry_rotate_returns_rcr_item() -> None:
    expect(_decode_shift_reg("rcr rax, cl") == ("shiftreg", "rcr", 0, 64))


def test_classify_carry_rotate_uses_shift_item() -> None:
    instruction = {"addr": 0x1000, "size": 3, "type": "rcl", "opcode": "rcl eax, 1"}
    expect(_classify(instruction) == ["shift", "rcl", 0, 1, 32])


def test_carry_rotate_handler_restores_virtual_carry_before_native_operation() -> None:
    assembly = _vshift_handler_asm("vshift_rcl_32", "r13b")
    expect("push qword ptr [rsp+128]" in assembly)
    expect("popfq" in assembly)
    expect("rcl eax, cl" in assembly)
