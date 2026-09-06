"""Contracts for the compact unwind metadata emitted for VM regions."""

import struct
from typing import cast

import pytest

from r2morph.analysis.exception_reader import ExceptionInfoReader
from r2morph.core.binary import Binary
from r2morph.platform.elf_unwind import VmEhFrameSpec, build_vm_eh_frame, build_vm_eh_frame_with_lsda
from tests.utils.assertions import expect

_HEADER_EH_FRAME_OFFSET = 16
_BLOB_TO_METADATA_DELTA = -0x10000
_VM_BLOB_ADDRESS = 0x500000
_VM_BLOB_SIZE = 0x180
_VM_METADATA_ADDRESS = 0x510000
_PERSONALITY_ADDRESS = 0x401090
_LANDING_PAD_ADDRESS = 0x401050


class _GeneratedUnwindBinary:
    def __init__(self, metadata: bytes, lsda_offset: int) -> None:
        self._metadata = metadata
        self._lsda_offset = lsda_offset

    def get_arch_info(self) -> dict[str, int | str]:
        return {"format": "ELF64", "bits": 64}

    def get_sections(self) -> list[dict[str, int | str]]:
        eh_frame_size = self._lsda_offset - 20
        return [
            {"name": ".eh_frame", "addr": _VM_METADATA_ADDRESS + 20, "size": eh_frame_size},
            {
                "name": ".gcc_except_table",
                "addr": _VM_METADATA_ADDRESS + self._lsda_offset,
                "size": len(self._metadata) - self._lsda_offset,
            },
        ]

    def read_bytes(self, address: int, size: int) -> bytes:
        if address == _VM_METADATA_ADDRESS + 20:
            return self._metadata[20 : 20 + size]
        if address == _VM_METADATA_ADDRESS + self._lsda_offset:
            return self._metadata[self._lsda_offset : self._lsda_offset + size]
        return b""


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


def test_vm_eh_frame_round_trips_remapped_lsda_call_site() -> None:
    metadata = build_vm_eh_frame_with_lsda(
        VmEhFrameSpec(
            _VM_BLOB_ADDRESS,
            _VM_BLOB_SIZE,
            0x400,
            _VM_METADATA_ADDRESS,
            ((0x20, 0x28, 0x123),),
            (0xFF, 0xFF, None, 8, bytes((0x01, 0x00))),
            ((_VM_BLOB_ADDRESS + 0x20, _VM_BLOB_ADDRESS + 0x28, _LANDING_PAD_ADDRESS, 1),),
            _PERSONALITY_ADDRESS,
        )
    )
    lsda_offset = metadata.rfind(bytes((0x1B,)))
    frames = ExceptionInfoReader(cast(Binary, _GeneratedUnwindBinary(metadata, lsda_offset))).read_exception_frames()

    frame = frames[_VM_BLOB_ADDRESS]
    expect(
        frame.personality == _PERSONALITY_ADDRESS
        and frame.lsda_address == _VM_METADATA_ADDRESS + lsda_offset
        and frame.landing_pads[0].address == _LANDING_PAD_ADDRESS
        and frame.landing_pads[0].metadata["call_site_start"] == _VM_BLOB_ADDRESS + 0x20
    )
