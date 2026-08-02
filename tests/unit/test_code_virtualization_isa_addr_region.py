"""The region VM threads a per-build address-fold personality (`addr_variant`).

The memory-address prologues route their `r10 += addend` MBA through `addr_fold`.
`addr_variant` 0 keeps the canonical, key-selected fold (byte-identical); a
non-zero variant changes it. The fold's own value-equivalence is proven in
test_code_virtualization_isa_addr.py; these tests check the spec draw and that the
region prologues actually consult the variant. Every memory/lea/indexed fixture in
the integration suite exercises these prologues, so a wrong fold surfaces there.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_fold import addr_fold
from r2morph.mutations.code_virtualization_region_handlers import _indexed_address_asm, _mem_address_asm
from r2morph.mutations.code_virtualization_region_isa import build_isa_spec

_KEY = 0x5A
_KD = "0x0"


def test_build_isa_spec_addr_variant_zero_is_canonical() -> None:
    assert build_isa_spec(0).addr_variant == 0


def test_addr_variant_diverges_across_seeds() -> None:
    variants = {build_isa_spec(seed).addr_variant for seed in range(1, 200)}
    assert len(variants) > 1


def test_mem_prologue_variant_zero_uses_the_canonical_fold() -> None:
    body, _ = _mem_address_asm(False, _KEY, _KD, 0, 0)
    assert addr_fold("rax", "rcx", _KEY, 0) in body


def test_mem_prologue_nonzero_variant_changes_the_fold() -> None:
    canonical, _ = _mem_address_asm(False, _KEY, _KD, 0, 0)
    varied, _ = _mem_address_asm(False, _KEY, _KD, 0, 1)
    assert canonical != varied


def test_indexed_prologue_threads_addr_variant() -> None:
    canonical, _ = _indexed_address_asm(_KEY, _KD, 0, 0)
    varied, _ = _indexed_address_asm(_KEY, _KD, 0, 1)
    assert canonical != varied
