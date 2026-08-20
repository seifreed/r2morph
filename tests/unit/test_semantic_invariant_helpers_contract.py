"""Contracts for semantic invariant helpers."""

from r2morph.validation.semantic_invariant_helpers import compute_stack_delta_for_bytes, normalize_architecture
from tests.utils.assertions import expect


def test_normalize_architecture_maps_common_families() -> None:
    expect(normalize_architecture("x86", 64) == "x86_64")
    expect(normalize_architecture("x86", 32) == "x86")
    expect(normalize_architecture("arm", 64) == "arm64")
    expect(normalize_architecture("arm64", 32) == "arm")
    expect(normalize_architecture("unknown", 64) == "unknown")


def test_compute_stack_delta_for_bytes_handles_push_pop_opcodes() -> None:
    code = b"\x50\x58"
    expect(compute_stack_delta_for_bytes(code, "x86_64", 8) == 0)
