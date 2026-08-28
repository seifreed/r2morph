"""Contract tests for the low-qword XMM register move."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_indexed,
    _decode_fp_mem,
    _decode_fp_move,
    _decode_fp_riprel,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import _fp_move_handler_asm
from tests.utils.assertions import expect


def test_fp_move_decoder_movq_register_copy_uses_q_mode() -> None:
    expect(_decode_fp_move("movq xmm1, xmm2") == ("fpmov", "q", 1, 2))


def test_fp_move_handler_movq_emits_low_qword_instruction() -> None:
    assembly = _fp_move_handler_asm("fpmov_q", "byte ptr [rsp+136]")
    expect("movq xmm0, xmm1" in assembly)


def test_fp_memory_decoder_movq_uses_qword_width() -> None:
    expect(_decode_fp_mem("movq xmm1, qword ptr [rax+8]") == ("fpload", 1, 0, 8, 64))


def test_fp_rip_relative_decoder_movq_preserves_target() -> None:
    expect(_decode_fp_riprel("movq xmm1, qword ptr [rip+8]", 0x1000, 8) == ("fploadrip", 1, 0x1010, 64))


def test_fp_indexed_decoder_movq_preserves_scaled_addressing() -> None:
    expect(_decode_fp_indexed("movq xmm1, qword ptr [rax + rdx*8 + 16]") == ("fploadidx", 1, 0, 2, 3, 16, 64))
