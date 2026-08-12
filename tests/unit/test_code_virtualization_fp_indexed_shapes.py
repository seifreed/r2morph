"""Contract tests for the two shapes of a scaled-index FP memory item.

``movsd/movss xmm, [base+index*scale+disp]`` decodes to a 7-field item, while the
no-base ``[index*scale+disp]`` form drops the base slot and decodes to a 6-field
``idxnb`` item. Every consumer picks the field layout from the ``nb`` suffix, so
the two shapes are a cross-module contract: the op-key builder, the byte-size
table and the straight-line engine's classifier all depend on where ``width``
sits. These pin that contract on the real decoders (no mocks, no binary).
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization import _decode_run_item
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_fp_decoders import _decode_fp_indexed
from r2morph.mutations.code_virtualization_region_models import _op_key


def test_op_key_of_based_fp_indexed_load_reports_the_decoded_width() -> None:
    # movsd xmm1, [rax + rdx*8 + 16]: the op key reads width out of the 7-field shape.
    assert _op_key(_decode_fp_indexed("movsd xmm1, [rax + rdx*8 + 16]")) == "fploadidx_64"


def test_op_key_of_no_base_fp_indexed_load_reports_the_decoded_width() -> None:
    # movss xmm1, [rdx*4 + 16]: no base slot, so width sits one field earlier.
    assert _op_key(_decode_fp_indexed("movss xmm1, [rdx*4 + 16]")) == "fploadidxnb_32"


def test_op_key_of_no_base_fp_indexed_store_reports_the_decoded_width() -> None:
    # movsd [rdx*8 + 16], xmm1: the store side uses the same no-base layout.
    assert _op_key(_decode_fp_indexed("movsd [rdx*8 + 16], xmm1")) == "fpstoreidxnb_64"


def test_no_base_fp_indexed_item_encodes_one_byte_shorter_than_the_based_form() -> None:
    based = _item_size(_decode_fp_indexed("movsd xmm1, [rax + rdx*8 + 16]"))

    assert _item_size(_decode_fp_indexed("movsd xmm1, [rdx*8 + 16]")) == based - 1


def test_straight_line_engine_virtualizes_the_based_fp_indexed_load() -> None:
    item = _decode_run_item("movsd xmm1, [rax + rdx*8 + 16]")

    assert item is not None


def test_straight_line_engine_leaves_the_no_base_fp_indexed_load_native() -> None:
    # The engine's FP memory op has no no-base indexed encoding, so the shorter
    # shape must be rejected rather than unpacked as if it carried a base slot.
    assert _decode_run_item("movsd xmm1, [rdx*8 + 16]") is None
