"""Unit contracts for memory-backed push region items."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region import _stack_transition
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_models import _op_key
from r2morph.mutations.code_virtualization_region_push import _decode_pop_memory, _decode_push_memory
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


def test_decode_push_and_pop_memory_support_word_width() -> None:
    expect(
        (
            _decode_push_memory("push word ptr [rax]"),
            _decode_pop_memory("pop word ptr [rax]"),
        )
        == (("pushmem", 0, 0, 16), ("popmem", 0, 0, 16))
    )


def test_decode_pop_memory_supports_all_address_shapes() -> None:
    expect(
        (
            _decode_pop_memory("pop qword ptr [rbp-8]"),
            _decode_pop_memory("pop qword ptr [rip+0x20]", 0x1000, 7),
            _decode_pop_memory("pop qword ptr [rax+rcx*8+16]"),
            _decode_pop_memory("pop qword ptr [rcx*8+16]"),
        )
        == (
            ("popmem", 5, -8, 64),
            ("popmemrip", 0x1027, 64),
            ("popmemidx", 0, 1, 3, 16, 64),
            ("popmemidxnb", 1, 3, 16, 64),
        )
    )


def test_push_memory_item_keys_include_width() -> None:
    expect(_op_key(("pushmem", 1, -8, 64)) == "pushmem_64")


def test_pop_memory_item_keys_include_width() -> None:
    expect(_op_key(("popmem", 1, -8, 64)) == "popmem_64")


def test_push_memory_item_sizes_match_address_shape() -> None:
    expect(
        (
            _item_size(("pushmem", 1, -8, 64)),
            _item_size(("pushmemrip", 0x402000, 64)),
            _item_size(("pushmemidx", 1, 2, 3, 16, 64)),
            _item_size(("pushmemidxnb", 2, 3, 16, 64)),
            _item_size(("popmem", 1, -8, 64)),
            _item_size(("popmemrip", 0x402000, 64)),
            _item_size(("popmemidx", 1, 2, 3, 16, 64)),
            _item_size(("popmemidxnb", 2, 3, 16, 64)),
        )
        == (7, 6, 9, 8, 7, 6, 9, 8)
    )


def test_classify_push_memory_uses_region_item() -> None:
    expect(
        _classify({"type": "push", "opcode": "push qword ptr [rax]", "addr": 0x1000, "size": 4})
        == ["pushmem", 0, 0, 64]
    )


def test_classify_pop_memory_uses_region_item() -> None:
    expect(
        _classify({"type": "pop", "opcode": "pop qword ptr [rax]", "addr": 0x1000, "size": 4}) == ["popmem", 0, 0, 64]
    )


def test_stack_balance_uses_declared_memory_width() -> None:
    expect(_stack_transition(["pushmem", 0, 0, 16], 0, None) == (2, None))
