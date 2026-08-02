"""
Per-build semantic ISA personality for the region VM.

``field_perm`` permutes each item's operand byte offsets and ``dup`` renumbers the
opcodes, but every build still realizes each operation with the *same handler
algebra* - the same flag-synthesis spelling, the same fold. Two builds are the
same machine wearing different labels.

This module gives each build a coherent, per-build choice of *which*
equivalent implementation each handler family uses, derived deterministically from
a single ``isa_seed``: a different machine, not a relabelled one. ``isa_seed`` 0 is
the canonical personality (every selection 0), byte-identical to the pre-feature
handlers, so existing seeds and builds are unchanged.

The spec is a value object of independent per-family selections. It currently
carries the flag-synthesis spelling vector (see
:mod:`code_virtualization_region_flags`); later families (arithmetic fold, shift,
compare) add one field each.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from r2morph.mutations.code_virtualization_fold import ARITH_VARIANT_BITS
from r2morph.mutations.code_virtualization_region_compare import COMPARE_VARIANT_BITS
from r2morph.mutations.code_virtualization_region_flags import FLAG_VARIANT_BITS


@dataclass(frozen=True)
class RegionISASpec:
    """The handler-implementation choices for one build (all 0 == canonical)."""

    flag_variant: int = 0
    arith_variant: int = 0
    compare_variant: int = 0


def build_isa_spec(isa_seed: int) -> RegionISASpec:
    """Derive this build's ISA personality from ``isa_seed`` (0 == canonical)."""
    if not isa_seed:
        return RegionISASpec()
    rng = random.Random(isa_seed)
    # Draw order is stable: appending a family keeps earlier fields byte-stable for
    # a given seed. flag_variant was first, then arith_variant, then compare_variant.
    flag_variant = rng.randrange(1 << FLAG_VARIANT_BITS)
    arith_variant = rng.randrange(1 << ARITH_VARIANT_BITS)
    compare_variant = rng.randrange(1 << COMPARE_VARIANT_BITS)
    return RegionISASpec(flag_variant=flag_variant, arith_variant=arith_variant, compare_variant=compare_variant)
