"""
Unit tests for the polymorphic self-checksum.

The per-byte mix step varies by instance so the checksum loop is not a fixed
byte signature an automated devirtualizer can match and strip. The asm builder
and the Python mirror both derive their step from the same variant, so they stay
in lockstep (runtime lockstep is covered by the exit-code integration tests; a
mismatch would break opcode cancellation and fail those).
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_integrity import (
    _CHECKSUM_OPS,
    _CHECKSUM_ROTATES,
    _checksum_bytes,
    _checksum_step,
    checksum_prologue_asm,
    compute_build_checksum,
)
from tests.utils.assertions import expect


def test_checksum_step_spans_every_op_rotate_and_amount() -> None:
    steps = [_checksum_step(v) for v in range(42)]
    expect({op for op, _, _ in steps} == set(_CHECKSUM_OPS))
    expect({rot for _, rot, _ in steps} == set(_CHECKSUM_ROTATES))
    expect({amount for _, _, amount in steps} == set(range(1, 8)))


def test_prologue_asm_emits_the_variant_step() -> None:
    # Variant 0 -> add/rol/1; pick a variant that exercises a different branch.
    op, rotate, amount = _checksum_step(15)
    asm = checksum_prologue_asm(15)
    expect(not (f"  {op} dl, byte ptr [rdi+0]\n" not in asm))
    expect(not (f"  {rotate} dl, {amount}\n" not in asm))


def test_checksum_traversal_permutates_each_block_in_variant_order() -> None:
    code = bytes(range(7))

    expect(
        {"low_first": tuple(_checksum_bytes(code, 0)), "permuted": tuple(_checksum_bytes(code, 84))}
        == {"low_first": (0, 1, 2, 3, 4, 5, 6), "permuted": (0, 2, 3, 1, 4, 6, 5)}
    )


def test_checksum_reverse_bytewise_mirrors_reversed_input() -> None:
    code = bytes(range(7))

    expect(tuple(_checksum_bytes(code, 0, bytewise=True, reverse=True)) == tuple(reversed(code)))


def test_prologue_asm_emits_guarded_tail_for_partial_block() -> None:
    asm = checksum_prologue_asm(0)

    expect("byte ptr [rdi+3]" in asm and "lea r8, [rdi+3]" in asm)


def test_compute_build_checksum_is_byte_sensitive() -> None:
    base = bytes(range(64))
    flipped = bytearray(base)
    flipped[30] ^= 0x01
    expect(compute_build_checksum(base, 7) != compute_build_checksum(bytes(flipped), 7))


def test_compute_build_checksum_varies_by_variant() -> None:
    code = bytes((i * 5 + 1) & 0xFF for i in range(48))
    # Two variants with genuinely different steps must not collapse to one value.
    expect(compute_build_checksum(code, 0) != compute_build_checksum(code, 20))
