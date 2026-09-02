"""Unit contracts for memory-backed push region items."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_models import _op_key
from r2morph.mutations.code_virtualization_region_push import _decode_push_memory
from tests.utils.assertions import expect


def test_decode_push_memory_base_form_returns_qword_item() -> None:
    expect(_decode_push_memory("push qword ptr [rbp-8]") == ("pushmem", 5, -8, 64))


def test_decode_push_memory_indexed_form_returns_qword_item() -> None:
    expect(_decode_push_memory("push qword ptr [rax+rcx*8+16]") == ("pushmemidx", 0, 1, 3, 16, 64))


def test_decode_push_memory_no_base_form_returns_qword_item() -> None:
    expect(_decode_push_memory("push qword ptr [rcx*8+16]") == ("pushmemidxnb", 1, 3, 16, 64))


def test_decode_push_memory_rip_relative_form_returns_absolute_target() -> None:
    expect(_decode_push_memory("push qword ptr [rip+0x20]", 0x1000, 7) == ("pushmemrip", 0x1027, 64))


def test_decode_push_memory_rejects_non_qword_form() -> None:
    expect(_decode_push_memory("push dword ptr [rax]") is None)


def test_push_memory_item_keys_include_width() -> None:
    expect(_op_key(("pushmem", 1, -8, 64)) == "pushmem_64")


def test_push_memory_item_sizes_match_address_shape() -> None:
    expect(
        (
            _item_size(("pushmem", 1, -8, 64)),
            _item_size(("pushmemrip", 0x402000, 64)),
            _item_size(("pushmemidx", 1, 2, 3, 16, 64)),
            _item_size(("pushmemidxnb", 2, 3, 16, 64)),
        )
        == (7, 6, 9, 8)
    )


def test_classify_push_memory_uses_region_item() -> None:
    expect(
        _classify({"type": "push", "opcode": "push qword ptr [rax]", "addr": 0x1000, "size": 4})
        == ["pushmem", 0, 0, 64]
    )
