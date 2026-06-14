"""Helper functions for byte-level binary diffing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from r2morph.validation.differ_models import ByteDiff

if TYPE_CHECKING:
    from r2morph.core.binary import Binary


def compare_section_bytes(
    original: Binary,
    mutated: Binary,
    orig_section: dict,
    mut_section: dict,
    context_bytes: int,
) -> list[ByteDiff]:
    """Compare bytes within a pair of sections."""
    diffs: list[ByteDiff] = []

    orig_addr = orig_section.get("addr", orig_section.get("virtual_address", 0))
    orig_size = orig_section.get("size", orig_section.get("virtual_size", 0))
    mut_size = mut_section.get("size", mut_section.get("virtual_size", 0))

    try:
        orig_data = original.read_bytes(orig_addr, min(orig_size, mut_size, 4096))
        mut_data = mutated.read_bytes(mut_section.get("addr", mut_section.get("virtual_address", 0)), min(orig_size, mut_size, 4096))
    except Exception:
        return diffs

    if orig_data is None or mut_data is None:
        return diffs

    return compute_byte_diffs(orig_data, mut_data, orig_addr, context_bytes)


def compute_byte_diffs(orig: bytes, mut: bytes, base_addr: int, context_bytes: int) -> list[ByteDiff]:
    """Compute byte-level differences with surrounding context."""
    diffs: list[ByteDiff] = []
    min_len = min(len(orig), len(mut))

    for i in range(min_len):
        if orig[i] != mut[i]:
            context_start = max(0, i - context_bytes)
            context_end = min(min_len, i + context_bytes + 1)

            diffs.append(
                ByteDiff(
                    offset=base_addr + i,
                    original=bytes([orig[i]]),
                    mutated=bytes([mut[i]]),
                    context_before=orig[context_start:i],
                    context_after=orig[i + 1 : context_end],
                )
            )

    if len(orig) != len(mut):
        start = min_len
        diffs.append(
            ByteDiff(
                offset=base_addr + start,
                original=orig[start:] if start < len(orig) else b"",
                mutated=mut[start:] if start < len(mut) else b"",
            )
        )

    return diffs
