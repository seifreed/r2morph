"""Unit coverage for semantically independent engine-handler variants."""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme
from r2morph.mutations.code_virtualization_engine_frame import DEFAULT_FRAME_LAYOUT
from r2morph.mutations.code_virtualization_engine_handlers import EngineHandlerGenerator
from r2morph.mutations.code_virtualization_engine_isa import EngineISASpec


def test_gp_handler_body_variant_reorders_independent_loads() -> None:
    scheme = build_vm_scheme(randomness.Random(20260820))
    generator = EngineHandlerGenerator(scheme, DEFAULT_FRAME_LAYOUT, EngineISASpec())

    canonical = generator.handler_body("mov", False, 64, 0, body_variant=0)
    reordered = generator.handler_body("mov", False, 64, 0, body_variant=1)

    field_variant = generator.handler_body("mov", False, 64, 0, body_variant=2)

    assert len({canonical, reordered, field_variant}) == 3
