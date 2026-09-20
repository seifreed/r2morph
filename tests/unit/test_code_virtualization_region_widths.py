"""Regression coverage for sub-dword virtual register semantics."""

from __future__ import annotations

import importlib

import pytest

from r2morph.mutations.code_virtualization_engine_models import VirtualizedOp
from r2morph.mutations.code_virtualization_layout import field_offsets
from r2morph.mutations.code_virtualization_region_handlers import (
    IntegerHandlerConfig,
    _op_mba_handler_asm,
)
from r2morph.mutations.code_virtualization_region_lowering import _lower_fold
from tests.utils.assertions import expect

_EXPECTED_BYTE_RESULT = 0x123456789ABCDEAA


def test_lower_fold_subdword_operation_uses_partial_pop() -> None:
    operation = VirtualizedOp("xor", 3, 4, False, 8)

    lowered = _lower_fold(["op", operation], "vbinop", False)

    expect(lowered[-1] == ["vpop8", 3])


def test_mba_byte_handler_preserves_register_upper_bits() -> None:
    keystone = pytest.importorskip("keystone")
    unicorn = pytest.importorskip("unicorn")
    x86 = importlib.import_module("unicorn.x86_const")
    handler = _op_mba_handler_asm(IntegerHandlerConfig("vsuper_xor_i_8", "0x00", "0x0", "0x0"))
    code_asm = handler.split("  add rsi,", 1)[0]
    assembler = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = assembler.asm(code_asm, 0x1000)
    offsets = field_offsets("vsuper_xor_i_8", 0)
    bytecode = bytearray(8)
    bytecode[offsets["dst"]] = 0
    bytecode[offsets["imm"]] = 0xAA

    machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    machine.mem_map(0x1000, 0x1000)
    machine.mem_write(0x1000, bytes(code))
    machine.mem_map(0x200000, 0x2000)
    machine.mem_map(0x300000, 0x1000)
    machine.mem_write(0x300000, bytes(bytecode))
    machine.mem_write(0x200000, (0x123456789ABCDE00).to_bytes(8, "little"))
    machine.reg_write(x86.UC_X86_REG_RSP, 0x200000)
    machine.reg_write(x86.UC_X86_REG_RSI, 0x300000)
    machine.reg_write(x86.UC_X86_REG_R13, 0)

    machine.emu_start(0x1000, 0x1000 + len(code))

    result = int.from_bytes(machine.mem_read(0x200000, 8), "little")
    expect(result == _EXPECTED_BYTE_RESULT)
