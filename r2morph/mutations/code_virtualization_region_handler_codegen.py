"""Per-opcode handler instance generation for region virtualization."""

from __future__ import annotations

import r2morph.core.randomness as random
from r2morph.mutations.code_virtualization_engine_rename import rename_local_body
from r2morph.mutations.code_virtualization_fold import ADDR_VARIANT_BITS, ARITH_VARIANT_BITS
from r2morph.mutations.code_virtualization_region_control_handlers import _junk_asm, _live_junk_asm
from r2morph.mutations.code_virtualization_region_handler_router import HandlerBodyRouter, HandlerContext
from r2morph.mutations.code_virtualization_region_isa import build_isa_spec


def handler_instances_asm(
    index_to_key: dict[int, str],
    context: HandlerContext,
    junk_rng: random.Random,
    extra: dict[str, str] | None = None,
) -> str:
    """Emit shuffled, independently diversified handler instances."""
    extra = extra or {}
    spec = build_isa_spec(context.isa_seed)
    router = HandlerBodyRouter(context)
    lines: list[str] = []
    emit_order = sorted(index_to_key)
    random.Random(context.body_seed ^ 0x9E3779B9).shuffle(emit_order)
    for index in emit_order:
        handler_key = index_to_key[index]
        instance_rng = random.Random((context.isa_seed << 16) ^ index)
        arithmetic = instance_rng.randrange(1 << ARITH_VARIANT_BITS) if context.isa_seed else spec.arith_variant
        address = instance_rng.randrange(1 << ADDR_VARIANT_BITS) if context.isa_seed else spec.addr_variant
        variants = (
            spec.flag_variant,
            arithmetic,
            spec.compare_variant,
            spec.shift_variant,
            address,
        )
        lines.append(f"H_{index}:\n{_live_junk_asm(junk_rng, index)}")
        body = extra.get(handler_key)
        if body is None:
            body = router.body(handler_key, index, variants)
        lines.append(rename_local_body(body, random.Random(context.body_seed ^ index)))
        lines.append(_junk_asm(junk_rng))
    return "".join(lines)
