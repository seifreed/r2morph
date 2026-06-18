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

from r2morph.mutations.code_virtualization_layout import field_offsets, mem_offsets, permuted_fields


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
