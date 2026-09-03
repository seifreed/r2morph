"""Contract tests for the two shapes of a scaled-index FP memory item.

``movsd/movss xmm, [base+index*scale+disp]`` decodes to a 7-field item, while the
no-base ``[index*scale+disp]`` form drops the base slot and decodes to a 6-field
``idxnb`` item. Every consumer picks the field layout from the ``nb`` suffix, so
the two shapes are a cross-module contract: the op-key builder, the byte-size
table and the straight-line engine's classifier all depend on where ``width``
sits. These pin that contract on the real decoders (no mocks, no binary).
"""

from __future__ import annotations

import pytest

from r2morph.mutations.code_virtualization import _decode_run_item
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_indexed,
    _decode_fp_vex_256_packed_arith,
    _decode_fp_vex_256_packed_move,
)
from r2morph.mutations.code_virtualization_region_handler_router import HandlerBodyRouter, HandlerContext
from r2morph.mutations.code_virtualization_region_models import _op_key
from tests.utils.assertions import expect


def test_op_key_of_based_fp_indexed_load_reports_the_decoded_width() -> None:
    # movsd xmm1, [rax + rdx*8 + 16]: the op key reads width out of the 7-field shape.
    expect(_op_key(_decode_fp_indexed("movsd xmm1, [rax + rdx*8 + 16]")) == "fploadidx_64")


def test_op_key_of_no_base_fp_indexed_load_reports_the_decoded_width() -> None:
    # movss xmm1, [rdx*4 + 16]: no base slot, so width sits one field earlier.
    expect(_op_key(_decode_fp_indexed("movss xmm1, [rdx*4 + 16]")) == "fploadidxnb_32")


def test_op_key_of_no_base_fp_indexed_store_reports_the_decoded_width() -> None:
    # movsd [rdx*8 + 16], xmm1: the store side uses the same no-base layout.
    expect(_op_key(_decode_fp_indexed("movsd [rdx*8 + 16], xmm1")) == "fpstoreidxnb_64")


def test_no_base_fp_indexed_item_encodes_one_byte_shorter_than_the_based_form() -> None:
    based = _item_size(_decode_fp_indexed("movsd xmm1, [rax + rdx*8 + 16]"))

    expect(_item_size(_decode_fp_indexed("movsd xmm1, [rdx*8 + 16]")) == based - 1)


def test_straight_line_engine_virtualizes_the_based_fp_indexed_load() -> None:
    item = _decode_run_item("movsd xmm1, [rax + rdx*8 + 16]")

    expect(item is not None)


def test_straight_line_engine_virtualizes_the_no_base_fp_indexed_load() -> None:
    expect(_decode_run_item("movsd xmm1, [rdx*8 + 16]") is not None)


def test_straight_line_engine_virtualizes_the_no_base_fp_indexed_arithmetic() -> None:
    item = _decode_run_item("addsd xmm1, [rdx*8 + 16]")

    expect(item is not None and item.base_index < 0 and item.index_index >= 0)


def test_region_router_routes_vex_rip_load_to_a_real_handler() -> None:
    context = HandlerContext("key", "key_qword", "key_dword", 0, "", "", "", 0, ())
    body = HandlerBodyRouter(context).body("fploadvexrip_64", 0, (0, 0, 0, 0, 0))

    expect(body != "")


def test_region_router_rejects_unknown_handler_key() -> None:
    context = HandlerContext("key", "key_qword", "key_dword", 0, "", "", "", 0, ())

    with pytest.raises(ValueError, match="No VM handler is registered"):
        HandlerBodyRouter(context).body("unsupported_opcode", 0, (0, 0, 0, 0, 0))


def test_vex_256_packed_add_reports_a_dedicated_item_shape() -> None:
    expect(_decode_fp_vex_256_packed_arith("vaddps ymm0, ymm1, ymm2") == ("fppackedvex256", "addps", 0, 1, 2))


def test_vex_256_variable_shift_reports_a_dedicated_item_shape() -> None:
    expect(_decode_fp_vex_256_packed_arith("vpslld ymm0, ymm1, ymm2") == ("fppackedvex256", "pslld", 0, 1, 2))


def test_vex_256_variable_integer_shift_reports_a_dedicated_item_shape() -> None:
    expect(_decode_fp_vex_256_packed_arith("vpsravd ymm0, ymm1, ymm2") == ("fppackedvex256", "psravd", 0, 1, 2))


def test_vex_256_packed_move_reports_a_dedicated_item_shape() -> None:
    expect(_decode_fp_vex_256_packed_move("vmovups ymm3, ymm4") == ("fpmovvex256", "full", 3, 4))
