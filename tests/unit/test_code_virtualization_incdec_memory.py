"""Classification contracts for memory ``inc``/``dec`` instructions."""

from r2morph.mutations.code_virtualization_region_classification import _classify_binary
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from tests.utils.assertions import expect

_DIRECT_MEMORY_ITEM_SIZE = 7
_RIP_MEMORY_ITEM_SIZE = 6
_INDEXED_MEMORY_ITEM_SIZE = 9
_INDEXED_NO_BASE_MEMORY_ITEM_SIZE = 8


def test_inc_memory_classification_preserves_base_and_width() -> None:
    expect(_classify_binary("add", "inc dword ptr [rax+4]", 0x1000, 4) == ["incdecmem", "inc", 0, 4, 32])


def test_dec_rip_memory_classification_resolves_absolute_target() -> None:
    expect(_classify_binary("sub", "dec qword ptr [rip+0x10]", 0x1000, 7) == ["incdecmemrip", "dec", 0x1017, 64])


def test_inc_memory_item_size_matches_direct_address_handler() -> None:
    expect(_item_size(("incdecmem", "inc", 0, 4, 32)) == _DIRECT_MEMORY_ITEM_SIZE)


def test_dec_rip_memory_item_size_matches_rip_address_handler() -> None:
    expect(_item_size(("incdecmemrip", "dec", 0x1017, 64)) == _RIP_MEMORY_ITEM_SIZE)


def test_inc_memory_classification_preserves_base_index_shape() -> None:
    expect(_classify_binary("add", "inc dword ptr [rax+rcx*4+8]", 0x1000, 5) == ["incdecmemidx", "inc", 0, 1, 2, 8, 32])


def test_dec_memory_classification_preserves_no_base_index_shape() -> None:
    expect(_classify_binary("sub", "dec qword ptr [rcx*8+16]", 0x1000, 5) == ["incdecmemidxnb", "dec", 1, 3, 16, 64])


def test_indexed_memory_item_sizes_match_address_handlers() -> None:
    expect(
        _item_size(("incdecmemidx", "inc", 0, 1, 2, 8, 32)) == _INDEXED_MEMORY_ITEM_SIZE
        and _item_size(("incdecmemidxnb", "dec", 1, 3, 16, 64)) == _INDEXED_NO_BASE_MEMORY_ITEM_SIZE
    )
