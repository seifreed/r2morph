"""Per-build semantic ISA personality for the straight-line engine VM.

The engine mirror of :mod:`code_virtualization_region_isa`. Where the region VM
carries a flag-synthesis axis, the engine only virtualizes flag-dead runs (see
:mod:`code_virtualization_engine`), so it has no flag axis at all: its sole
per-build handler-algebra choice is the arithmetic fold variant, shared with the
region VM through :func:`code_virtualization_fold.arith_fold`.

``engine_isa_seed`` 0 is the canonical personality (``arith_variant`` 0, which
delegates verbatim to the shared ``_op_mba_compute``), so existing engine builds
are byte-identical. A later family adds one field here, exactly as on the region
side.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from r2morph.mutations.code_virtualization_fold import ARITH_VARIANT_BITS


@dataclass(frozen=True)
class EngineISASpec:
    """The handler-implementation choices for one engine build (0 == canonical)."""

    arith_variant: int = 0


def build_engine_isa_spec(engine_isa_seed: int) -> EngineISASpec:
    """Derive this build's engine ISA personality from ``engine_isa_seed`` (0 == canonical)."""
    if not engine_isa_seed:
        return EngineISASpec()
    return EngineISASpec(arith_variant=random.Random(engine_isa_seed).randrange(1 << ARITH_VARIANT_BITS))
