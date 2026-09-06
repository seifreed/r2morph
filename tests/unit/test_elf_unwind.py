"""Contracts for the compact unwind metadata emitted for VM regions."""

import struct

import pytest

from r2morph.platform.elf_unwind import build_vm_eh_frame
from tests.utils.assertions import expect

_HEADER_EH_FRAME_OFFSET = 16
_BLOB_TO_METADATA_DELTA = -0x10000


def test_vm_eh_frame_header_points_to_one_fde() -> None:
    metadata = build_vm_eh_frame(0x500000, 0x180, 0x400, 0x510000)

    expect(
        metadata[:4] == bytes((1, 0x1B, 0x03, 0x3B))
        and struct.unpack_from("<i", metadata, 4)[0] == _HEADER_EH_FRAME_OFFSET
        and struct.unpack_from("<I", metadata, 8)[0] == 1
        and struct.unpack_from("<i", metadata, 12)[0] == _BLOB_TO_METADATA_DELTA
    )


def test_vm_eh_frame_rejects_invalid_blob_range() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        build_vm_eh_frame(0x500000, 0, 0x400, 0x510000)


def test_vm_eh_frame_adds_relocated_call_cfa_rows() -> None:
    metadata = build_vm_eh_frame(0x500000, 0x180, 0x400, 0x510000, ((0x20, 0x28, 0x123),))

    expect(bytes((0x02, 0x19, 0x0E, 0xA3, 0x02, 0x02, 0x08, 0x0E, 0x88, 0x08)) in metadata)


def test_vm_eh_frame_rejects_call_range_outside_blob() -> None:
    with pytest.raises(ValueError, match="outside"):
        build_vm_eh_frame(0x500000, 0x180, 0x400, 0x510000, ((0x01, 0x08, 0x123),))
