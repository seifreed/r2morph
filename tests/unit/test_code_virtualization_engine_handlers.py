"""Unit coverage for semantically independent engine-handler variants."""

from __future__ import annotations

from r2morph.core import randomness
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


def test_packed_immediate_handler_emits_shift_family() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    body = generator.handler_body("fppackedimm", False, 128, 0)

    expect("pslld xmm0, xmm1" in body and "psrad xmm0, xmm1" in body)
