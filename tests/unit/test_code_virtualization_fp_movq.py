"""Contract tests for the low-qword XMM register move."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_fp_decoders import _decode_fp_move
from r2morph.mutations.code_virtualization_region_fp_handlers import _fp_move_handler_asm
from tests.utils.assertions import expect


def test_fp_move_decoder_movq_register_copy_uses_q_mode() -> None:
    expect(_decode_fp_move("movq xmm1, xmm2") == ("fpmov", "q", 1, 2))


def test_fp_move_handler_movq_emits_low_qword_instruction() -> None:
    assembly = _fp_move_handler_asm("fpmov_q", "byte ptr [rsp+136]")
    expect("movq xmm0, xmm1" in assembly)
