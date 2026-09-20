"""Contracts for x86 rotates through the virtual carry flag."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region import _lower_arith_to_microops
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_decoders import (
    _decode_double_shift,
    _decode_shift,
    _decode_shift_reg,
)
from r2morph.mutations.code_virtualization_region_microops import _vdouble_shift_handler_asm, _vshift_handler_asm
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


def test_decode_double_shift_keeps_both_register_operands() -> None:
    expect(_decode_double_shift("shld eax, edx, 3") == ("shld", 0, 2, 3, 32))


def test_double_shift_handler_executes_native_flag_setting_operation() -> None:
    assembly = _vdouble_shift_handler_asm("vdouble_shift_shld_32", "r13b")
    expect("popfq" in assembly and "shld eax, r11d, cl" in assembly and "pushfq" in assembly)


def test_double_shift_lowers_to_two_operands_and_one_flagged_microop() -> None:
    expect(
        _lower_arith_to_microops([["shld", 0, 2, 3, 32]])
        == [["vpush", 0], ["vpush", 2], ["vdouble_shift", "shld", 3, 32], ["vpop", 0]]
    )
