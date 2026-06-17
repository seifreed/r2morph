"""
Unit tests for the mixed-boolean-arithmetic (MBA) address computation.

The shared address prologues must fold the displacement with the MBA identity
``a + b == (a ^ b) + 2*(a & b)`` instead of a literal ``add``, so the handler's
address arithmetic is not a plain pattern. Semantics are covered by the memory
fixtures; these tests pin the obfuscation form on the real builders.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_handlers import (
    _indexed_address_asm,
    _mem_address_asm,
)


def test_base_displacement_address_uses_mba_not_literal_add() -> None:
    asm, _ = _mem_address_asm(False, 0x6C, "0x6c6c6c6c")
    assert "add r10, rax" not in asm
    assert "lea r10, [rcx + r10*2]" in asm


def test_rip_relative_address_uses_mba_not_literal_add() -> None:
    asm, _ = _mem_address_asm(True, 0x6C, "0x6c6c6c6c")
    assert "add r10, rax" not in asm
    assert "lea r10, [rcx + r10*2]" in asm


def test_indexed_address_uses_mba_for_the_displacement() -> None:
    asm, _ = _indexed_address_asm(0x6C, "0x6c6c6c6c")
    # The base add stays a real add, but the displacement fold is MBA.
    assert "add r10, rax" not in asm
    assert "lea r10, [rcx + r10*2]" in asm
