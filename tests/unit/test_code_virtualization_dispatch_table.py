"""
Unit tests for the region VM's encrypted dispatch table.

The handler-offset table must not be a plaintext jump table a disassembler can
recover as a switch: each entry is XOR-encrypted with a per-instance key and the
dispatch decrypts it before jumping. These tests pin that contract on the real
scheme/interpreter builders (no mocks, no binary).
"""

from __future__ import annotations

import random
from typing import Any

from r2morph.mutations.code_virtualization_region import (
    build_region_scheme,
    extract_region,
)
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm


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
