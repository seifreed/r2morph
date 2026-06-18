"""
Unit tests for the per-build operand field layout (polymorphic VM ISA).

The encoder and the handlers both derive each item's operand offsets from
``field_perm`` via this module, so a build lays operands out in its own order. A
devirtualizer that models one sample's field offsets does not carry over to
another. ``field_perm`` 0 must be the identity layout (byte-identical to the
pre-feature encoding); a non-zero seed may reorder the operand fields while
keeping the opcode at offset 0 and the item's total size unchanged. Exit-code
tests pass with or without permutation, so the layout property needs its own
assertion.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_layout import (
    field_offsets,
    idx_offsets,
    imul3_offsets,
    mem_offsets,
    op_offsets,
    permuted_fields,
    shift_offsets,
)


def test_identity_layout_matches_legacy_fixed_offsets() -> None:
    # perm 0 must reproduce the historical hardcoded offsets: dst slot right after
    # the opcode, then the source slot / immediate.
    assert field_offsets("op_add_i_32", 0) == {"dst": 1, "imm": 2}
    assert field_offsets("op_add_i_64", 0) == {"dst": 1, "imm": 2}
    assert field_offsets("op_add_r_64", 0) == {"dst": 1, "src": 2}
    assert field_offsets("opmba_add_i_32", 0) == {"dst": 1, "imm": 2}


def test_memory_layout_identity_and_polymorphism() -> None:
    # The base+disp memory family (load/store/lea/cmp/op/movx) shares one layout:
    # perm 0 is the legacy reg@1, base@2, disp@3; rip-relative drops the base.
    assert mem_offsets(False, 0) == {"reg": 1, "base": 2, "disp": 3}
    assert mem_offsets(True, 0) == {"reg": 1, "disp": 2}
    # Three operand fields give up to six orders, so memory is the kind where the
    # per-build distinctness actually scales.
    layouts = {tuple(sorted(mem_offsets(False, seed).items())) for seed in range(1, 60)}
    assert len(layouts) > 2


def test_op_offsets_by_immediate_width_matches_the_string_key_path() -> None:
    # The engine keys arith handlers by (is_immediate, width); op_offsets must
    # agree with the region's string-key field_offsets so both VMs share one
    # layout core, and identity (perm 0) must be the legacy packing.
    assert op_offsets(True, 32, 0) == {"dst": 1, "imm": 2}
    assert op_offsets(False, 64, 0) == {"dst": 1, "src": 2}
    assert op_offsets(True, 32, 7) == field_offsets("op_add_i_32", 7)
    assert op_offsets(False, 64, 7) == field_offsets("op_add_r_64", 7)


def test_shift_and_imul3_layouts_identity_and_polymorphism() -> None:
    # The remaining low-arity region kinds: shift (slot, count) and three-operand
    # imul (dst, src, immediate). perm 0 is the legacy packing; both permute.
    assert shift_offsets(0) == {"slot": 1, "count": 2}
    assert imul3_offsets(0) == {"dst": 1, "src": 2, "imm": 3}
    assert len({tuple(sorted(shift_offsets(s).items())) for s in range(1, 20)}) > 1
    assert len({tuple(sorted(imul3_offsets(s).items())) for s in range(1, 40)}) > 2


def test_indexed_layout_identity_and_polymorphism() -> None:
    # Scaled-index items have five fields (reg/base/index/shift/disp), so the
    # layout has up to 120 orders - the richest per-build distinctness. The
    # no-base form drops the base field. perm 0 is the legacy packing.
    assert idx_offsets(False, 0) == {"reg": 1, "base": 2, "index": 3, "shift": 4, "disp": 5}
    assert idx_offsets(True, 0) == {"reg": 1, "index": 2, "shift": 3, "disp": 4}
    layouts = {tuple(sorted(idx_offsets(False, seed).items())) for seed in range(1, 80)}
    assert len(layouts) > 5


def test_some_seed_reorders_the_operand_fields() -> None:
    # The layout is genuinely polymorphic: at least one build order differs from
    # the identity order, so the field offsets are not fixed across samples.
    layouts = {tuple(sorted(field_offsets("op_add_i_32", seed).items())) for seed in range(1, 40)}
    assert len(layouts) > 1


def test_opcode_stays_first_and_fields_pack_contiguously() -> None:
    # Whatever the order, operands occupy a contiguous run starting at offset 1
    # (the opcode owns offset 0) and the item's total size is unchanged - only the
    # field positions move, so advance/decode stay correct.
    for key in ("op_add_i_64", "op_add_r_32", "opmba_xor_r_64"):
        for seed in (0, 1, 5, 99):
            fields = permuted_fields(key, seed)
            offsets = field_offsets(key, seed)
            assert min(offsets.values()) == 1
            spans = sorted((offsets[name], offsets[name] + size) for name, size in fields)
            # Contiguous, non-overlapping packing immediately after the opcode.
            assert spans[0][0] == 1
            for (_, end), (start, _) in zip(spans[:-1], spans[1:], strict=True):
                assert start == end
