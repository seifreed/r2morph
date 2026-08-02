"""
Unit tests for the region VM's encrypted dispatch table.

The handler-offset table must not be a plaintext jump table a disassembler can
recover as a switch: each entry is XOR-encrypted with a per-instance key and the
dispatch decrypts it before jumping. These tests pin that contract on the real
scheme/interpreter builders (no mocks, no binary).
"""

from __future__ import annotations

import random
import re
from typing import Any

from r2morph.mutations.code_virtualization_region import (
    build_region_scheme,
    extract_region,
)
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_region_models import _DWORD_BROADCAST


def _tiny_region() -> Any:
    # mov edi, 0x2a ; mov eax, 0x3c ; syscall  — a minimal reducible region.
    instructions = [
        {"addr": 0x1000, "type": "mov", "opcode": "mov edi, 0x2a", "size": 5, "jump": -1},
        {"addr": 0x1005, "type": "mov", "opcode": "mov eax, 0x3c", "size": 5, "jump": -1},
        {"addr": 0x100A, "type": "swi", "opcode": "syscall", "size": 2, "jump": -1},
    ]
    region = extract_region(instructions)
    assert region is not None
    return region


def test_scheme_generates_nonzero_table_key() -> None:
    scheme = build_region_scheme(_tiny_region(), random.Random(0))
    assert 1 <= scheme.table_key < (1 << 32)


def test_dispatch_decrypts_the_table_with_the_scheme_key() -> None:
    region = _tiny_region()
    scheme = build_region_scheme(region, random.Random(0))
    asm = _interpreter_asm(region, scheme)
    # The dispatch must XOR each loaded table entry with the per-instance key
    # before sign-extending and jumping; without it the table would be plaintext.
    assert f"xor eax, {hex(scheme.table_key)}" in asm


def test_dispatch_diffuses_the_table_key_with_the_self_checksum() -> None:
    # The table-entry decrypt also folds in the runtime self-checksum (broadcast
    # to 32 bits), so tampering corrupts handler resolution, not just opcodes.
    region = _tiny_region()
    scheme = build_region_scheme(region, random.Random(0))
    asm = _interpreter_asm(region, scheme)
    assert "imul ecx, ecx, 0x1010101" in asm


def test_handlers_position_unmask_their_slot_operands() -> None:
    # Operands carry the opcode's stream position, so a handler un-masks the slot
    # byte with r13b (the position the dispatch left there) - not a lone constant
    # key any single handler would reveal.
    region = _tiny_region()
    scheme = build_region_scheme(region, random.Random(0))
    asm = _interpreter_asm(region, scheme)
    # The scratch register holding the slot byte is renamed per handler, so match
    # any numbered scratch byte (the dispatch uses ``al`` for the opcode, so this
    # only matches a handler's operand un-mask, not the dispatch decode).
    assert re.search(r"xor r\d+b, r13b", asm)


def test_handlers_position_unmask_their_immediates() -> None:
    # The tiny region's mov-immediate handlers un-mask the immediate with the
    # position broadcast to 32 bits, so the immediate decrypt is keyed by
    # key XOR position, varying per item.
    region = _tiny_region()
    scheme = build_region_scheme(region, random.Random(0))
    asm = _interpreter_asm(region, scheme)
    # The immediate-decrypt register is renamed per handler; both operands are the
    # same scratch register whatever it renames to, so match the broadcast multiply
    # by an identical register pair.
    assert re.search(rf"imul (\w+), \1, {re.escape(hex(_DWORD_BROADCAST))}", asm)


def test_checksum_slot_is_relocated_per_build_within_the_free_frame_gap() -> None:
    # The self-checksum byte must not sit at a fixed frame offset every build: it is
    # drawn per build into the free gap above the flags slot (0x80) and below the xmm
    # save area (0x100), qword-aligned, so it is not a stable frame fingerprint.
    offsets = {build_region_scheme(_tiny_region(), random.Random(seed)).checksum_offset for seed in range(64)}
    assert len(offsets) > 1
    assert all(0x88 <= off < 0x100 and off % 8 == 0 for off in offsets)


def test_interpreter_folds_the_relocated_checksum_slot() -> None:
    # The dispatch's opcode decrypt reads the checksum from the build's relocated
    # slot, not the historical 0x88, so the relocation actually reaches the asm.
    region = _tiny_region()
    scheme = build_region_scheme(region, random.Random(0))
    asm = _interpreter_asm(region, scheme)
    assert f"[rsp+{scheme.checksum_offset}]" in asm


def test_flags_slot_is_relocated_per_build_distinct_from_checksum() -> None:
    # The captured-RFLAGS byte must not sit at a fixed frame offset every build: it
    # is relocated per build into the free frame gap, qword-aligned, and never
    # collides with the checksum slot.
    schemes = [build_region_scheme(_tiny_region(), random.Random(seed)) for seed in range(64)]
    assert len({s.flags_offset for s in schemes}) > 1
    assert all(0x80 <= s.flags_offset < 0x100 and s.flags_offset % 8 == 0 for s in schemes)
    assert all(s.flags_offset != s.checksum_offset for s in schemes)


def _branching_region() -> Any:
    # cmp/jle captures RFLAGS and the branch consumes it, so the interpreter emits
    # flag references - unlike the tiny mov/mov/syscall region.
    instructions = [
        {"addr": 0x1000, "type": "mov", "opcode": "mov edi, 0x2a", "size": 5, "jump": -1},
        {"addr": 0x1005, "type": "cmp", "opcode": "cmp edi, 0x10", "size": 3, "jump": -1},
        {"addr": 0x1008, "type": "cjmp", "opcode": "jle 0x1011", "size": 2, "jump": 0x1011},
        {"addr": 0x100A, "type": "mov", "opcode": "mov eax, 0x3c", "size": 5, "jump": -1},
        {"addr": 0x100F, "type": "swi", "opcode": "syscall", "size": 2, "jump": -1},
        {"addr": 0x1011, "type": "mov", "opcode": "mov eax, 0x3c", "size": 5, "jump": -1},
        {"addr": 0x1016, "type": "swi", "opcode": "syscall", "size": 2, "jump": -1},
    ]
    region = extract_region(instructions)
    assert region is not None
    return region


def test_interpreter_relocates_the_flags_slot_off_the_canonical_offset() -> None:
    # The flag references are moved off the canonical [rsp+128] slot to the build's
    # relocated offset, with no reference left at the fixed location.
    region = _branching_region()
    scheme = next(
        s for s in (build_region_scheme(region, random.Random(seed)) for seed in range(64)) if s.flags_offset != 0x80
    )
    asm = _interpreter_asm(region, scheme)
    assert not re.search(r"\[rsp\s*\+\s*128\]", asm)
    assert f"[rsp + {scheme.flags_offset}]" in asm
