"""Unit coverage for semantically independent engine-handler variants."""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_engine_codegen import _handler_body_variant
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme
from r2morph.mutations.code_virtualization_engine_frame import DEFAULT_FRAME_LAYOUT
from r2morph.mutations.code_virtualization_engine_handlers import EngineHandlerGenerator
from r2morph.mutations.code_virtualization_engine_isa import EngineISASpec
from tests.utils.assertions import expect

_EXPECTED_LEN_CANONICAL_REORDERED_FIELD_VARIANT_3 = 3


def test_gp_handler_body_variant_reorders_independent_loads() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    canonical = generator.handler_body("mov", False, 64, 0, body_variant=0)
    reordered = generator.handler_body("mov", False, 64, 0, body_variant=1)

    field_variant = generator.handler_body("mov", False, 64, 0, body_variant=2)

    expect(len({canonical, reordered, field_variant}) == _EXPECTED_LEN_CANONICAL_REORDERED_FIELD_VARIANT_3)


def test_handler_body_variant_uses_equivalent_vip_advance_form() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    add_form = generator.handler_body("mov", False, 64, 0, body_variant=0)
    lea_form = generator.handler_body("mov", False, 64, 0, body_variant=2)

    expect("add rsi" in add_form and "lea rsi" in lea_form)


def test_fp_convert_body_variant_uses_equivalent_sse2_move_encoding() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    canonical = generator.handler_body("cvti2f64", False, 64, 0, body_variant=0)
    diversified = generator.handler_body("cvti2f64", False, 64, 0, body_variant=1)

    expect(
        "movups xmm0, xmmword ptr [r10]" in canonical
        and "movdqu xmm0, xmmword ptr [r10]" in diversified
        and canonical.replace("movups", "xmmmove") == diversified.replace("movdqu", "xmmmove")
    )


def test_fp_convert_body_variant_keeps_vip_advance_form() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    body = generator.handler_body("cvti2f64", False, 64, 0, body_variant=2)

    expect("lea rsi, [rsi + 3]" in body)


def test_fp_convert_body_variant_precomputes_gp_slot_address() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    body = generator.handler_body("cvti2f64", False, 64, 0, body_variant=4)

    expect(
        "lea r11, [rsp + r9*8]" in body
        and "mov rax, qword ptr [r11]" in body
        and "mov rax, qword ptr [rsp + r9*8]" not in body
    )


def test_seeded_structural_body_variant_uses_equivalent_gp_and_fp_forms() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())
    gp_body = generator.handler_body("mov", False, 64, 0, body_variant=0)
    gp_variant = generator.handler_body("mov", False, 64, 0, body_variant=2)
    fp_body = generator.handler_body("fpmul", False, 32, 0, body_variant=0)
    fp_variant = generator.handler_body("fpmul", False, 32, 0, body_variant=4)
    seeded_variants = {_handler_body_variant(20260820, index, None) for index in range(64)}

    expected_gp_variant = gp_body.replace("movzx r8d, byte ptr", "mov r8d, 0\n  mov r8b, byte ptr")
    expected_gp_variant = expected_gp_variant.replace("movzx r9d, byte ptr", "mov r9d, 0\n  mov r9b, byte ptr")
    expect(expected_gp_variant.replace("add rsi, 3", "lea rsi, [rsi + 3]") == gp_variant)
    expect(fp_body.replace("movups", "movdqu") == fp_variant)
    expect(any(variant & 2 for variant in seeded_variants) and any(variant & 4 for variant in seeded_variants))


def test_packed_byte_shuffle_handler_emits_ssse3_operation() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    body = generator.handler_body("pshufb", False, 128, 0)

    expect("pshufb xmm0, xmm1" in body)


def test_packed_handler_selector_emits_register_shift_family() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    body = generator.handler_body("fppacked", False, 128, 0)

    expect("cmp ecx" in body and "psllw xmm0, xmm1" in body and "pmaxub xmm0, xmm1" in body)


def test_packed_handler_selector_emits_word_compare_family() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    body = generator.handler_body("fppacked", False, 128, 0)

    expect("pcmpeqw xmm0, xmm1" in body and "pcmpgtw xmm0, xmm1" in body)


def test_packed_immediate_handler_emits_shift_family() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    body = generator.handler_body("fppackedimm", False, 128, 0)

    expect("pslld xmm0, xmm1" in body and "psrad xmm0, xmm1" in body)
