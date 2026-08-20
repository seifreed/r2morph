"""
The computed-jump target map is load-base independent.

The region interpreter is position-independent by design: rip-relative data
references are stored as signed deltas from the bytecode base and the dispatch table
stores label differences. The computed-jump (``ijmp``) target map was the one place
keyed on link-time absolute addresses, which cannot match in a relocated image: the
handler compares the map against a runtime target ``load_base + link_address`` while
the map holds ``link_address``, so every entry misses and the scan falls through to
the VM exit - a silently wrong branch.

These pin the fix. The map keys the delta between its own label and the target, so a
uniform rebase (the map and the target move together, as they do inside one image)
leaves the stored key unchanged, and the handler normalizes the runtime target the
same way before comparing. A non-relocated image sees the identical delta, so the
non-PIE contract - covered by the runtime parity tests in the integration suite - is
unchanged.
"""

from __future__ import annotations

import struct

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm, build_region_blob
from r2morph.mutations.code_virtualization_region_models import Region
from tests.utils.assertions import expect

_TARGET_VADDR = 0x1017
_CAVE_VADDR = 0x500000
_REBASE = 0x400000
_TARGET_BYTECODE_OFFSET = 2  # the encoder's offset for the target item (ijmp is 2 bytes)
_MAP_ENTRY_SIZE = 12  # an 8-byte key followed by a 4-byte bytecode offset


def _ijmp_region(target_vaddr: int) -> Region:
    """A minimal region: a computed jump whose target maps to the exit item."""
    return Region(
        instructions=[("ijmp", 0), ("exit", 0x2000)],
        exit_vaddr=0x2000,
        entry_vaddr=0x1000,
        op_keys={"ijmp", "exit_8192"},
        body_ranges=[(0x1010, 2)],
        target_map={target_vaddr: 1},
    )


def _map_entry_bytes(blob: bytes) -> bytes:
    """The assembled bytes of the region's single map entry.

    The map is a ``.long`` count followed by that many entries, so with one target it
    is a count of 1 immediately followed by the 8-byte key and the target's bytecode
    offset. Locating it by the count and the offset keeps the search independent of
    the key under test.
    """
    matches = [
        offset
        for offset in range(len(blob) - 4 - _MAP_ENTRY_SIZE)
        if struct.unpack_from("<I", blob, offset)[0] == 1
        and struct.unpack_from("<I", blob, offset + 12)[0] == _TARGET_BYTECODE_OFFSET
    ]
    expect(len(matches) == 1, f"expected exactly one computed-jump map, found {len(matches)}")
    return blob[matches[0] + 4 : matches[0] + 4 + _MAP_ENTRY_SIZE]


def test_ijmp_map_entry_emits_map_relative_delta_instead_of_target_address() -> None:
    """The emitted key is ``ijmp_map - target``, so the map holds no absolute address."""
    region = _ijmp_region(_TARGET_VADDR)
    asm = _interpreter_asm(region, build_region_scheme(region, randomness.Random(1234)))
    expect(not (f"  .quad ijmp_map - {_TARGET_VADDR}\n" not in asm))


def test_ijmp_map_entry_bytes_unchanged_under_uniform_rebase() -> None:
    """Moving the blob and its target by one load base leaves the stored key identical."""
    at_base = _ijmp_region(_TARGET_VADDR)
    rebased = _ijmp_region(_TARGET_VADDR + _REBASE)
    at_base_blob = build_region_blob(at_base, _CAVE_VADDR, build_region_scheme(at_base, randomness.Random(1234)))
    rebased_blob = build_region_blob(
        rebased, _CAVE_VADDR + _REBASE, build_region_scheme(rebased, randomness.Random(1234))
    )
    expect(at_base_blob is not None and rebased_blob is not None)
    expect(_map_entry_bytes(at_base_blob) == _map_entry_bytes(rebased_blob))


def test_ijmp_handler_normalizes_runtime_target_against_map_address() -> None:
    """The scan negates the runtime target and adds the map's runtime address."""
    region = _ijmp_region(_TARGET_VADDR)
    asm = _interpreter_asm(region, build_region_scheme(region, randomness.Random(1234)))
    expect(not ("  lea r11, [rip+ijmp_map]\n  neg r10\n  add r10, r11\n" not in asm))
