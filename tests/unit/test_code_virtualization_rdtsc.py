"""Contracts for the x86 timestamp-counter VM handler."""

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_control_handlers import _rdtsc_handler_asm
from r2morph.mutations.code_virtualization_region_models import _op_key
from tests.utils.assertions import expect


def test_rdtsc_classification_returns_identity_item() -> None:
    item = _classify({"type": "unknown", "opcode": "rdtsc"})

    expect(item == ["rdtsc"])


def test_rdtsc_identity_item_has_one_byte_encoding() -> None:
    expect(_item_size(("rdtsc",)) == 1)


def test_rdtsc_identity_item_uses_named_handler_key() -> None:
    expect(_op_key(("rdtsc",)) == "rdtsc")


def test_rdtsc_handler_stores_both_timestamp_registers() -> None:
    assembly = _rdtsc_handler_asm(tuple(range(16)))

    expect("  rdtsc\n  mov qword ptr [rsp+0], rax\n  mov qword ptr [rsp+16], rdx\n" in assembly)
