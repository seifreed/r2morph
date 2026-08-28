"""Contract tests for the low-qword XMM register move."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_indexed,
    _decode_fp_mem,
    _decode_fp_movd,
    _decode_fp_move,
    _decode_fp_packed_mem,
    _decode_fp_riprel,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import _fp_movd_handler_asm, _fp_move_handler_asm
from tests.utils.assertions import expect


def test_fp_move_decoder_movq_register_copy_uses_q_mode() -> None:
    expect(_decode_fp_move("movq xmm1, xmm2") == ("fpmov", "q", 1, 2))


def test_fp_move_decoder_movdqa_register_copy_uses_full_mode() -> None:
    expect(_decode_fp_move("movdqa xmm1, xmm2") == ("fpmov", "full", 1, 2))


def test_fp_packed_memory_decoder_movdqu_uses_full_width_move() -> None:
    expect(_decode_fp_packed_mem("movdqu xmm1, xmmword ptr [rax+8]") == ("fppload", 1, 0, 8))


def test_vector_classifier_virtualizes_movdqu_memory_load() -> None:
    expect(
        _classify(
            {
                "type": "mov",
                "family": "vec",
                "opcode": "movdqu xmm1, xmmword ptr [rax+8]",
                "addr": 0x1000,
                "size": 8,
            }
        )
        == ["fppload", 1, 0, 8]
    )


def test_fp_move_handler_movq_emits_low_qword_instruction() -> None:
    assembly = _fp_move_handler_asm("fpmov_q", "byte ptr [rsp+136]")
    expect("movq xmm0, xmm1" in assembly)


def test_fp_memory_decoder_movq_uses_qword_width() -> None:
    expect(_decode_fp_mem("movq xmm1, qword ptr [rax+8]") == ("fpload", 1, 0, 8, 64))


def test_fp_rip_relative_decoder_movq_preserves_target() -> None:
    expect(_decode_fp_riprel("movq xmm1, qword ptr [rip+8]", 0x1000, 8) == ("fploadrip", 1, 0x1010, 64))


def test_fp_indexed_decoder_movq_preserves_scaled_addressing() -> None:
    expect(_decode_fp_indexed("movq xmm1, qword ptr [rax + rdx*8 + 16]") == ("fploadidx", 1, 0, 2, 3, 16, 64))


def test_fp_movd_decoder_gp_source_uses_xmm_and_gp_slots() -> None:
    expect(_decode_fp_movd("movd xmm3, eax") == ("fpmovd", "gp_to_xmm", 3, 0))


def test_fp_movd_decoder_xmm_source_uses_xmm_and_gp_slots() -> None:
    expect(_decode_fp_movd("movd edi, xmm3") == ("fpmovd", "xmm_to_gp", 3, 7))


def test_fp_movd_handler_gp_source_zeroes_xmm_destination() -> None:
    assembly = _fp_movd_handler_asm("fpmovd_gp_to_xmm", "byte ptr [rsp+136]")
    expect("movd xmm0, eax" in assembly)


def test_fp_movd_handler_xmm_source_zero_extends_gp_destination() -> None:
    assembly = _fp_movd_handler_asm("fpmovd_xmm_to_gp", "byte ptr [rsp+136]")
    expect("movd eax, xmm0" in assembly)
