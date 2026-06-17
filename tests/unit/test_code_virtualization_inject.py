"""
Regression: the physical blob writer must round-trip blobs larger than r2's
command buffer.

A single ``wx <hex>`` command is truncated past r2's ~4 KiB line buffer, so a VM
blob over ~2 KiB (routine once nesting is enabled) was written corrupt and the
injection's own read-back rejected it - silently dropping the mutation. The
writer chunks the I/O; this pins that a large blob survives the round trip.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization_inject import _file_size, _read_physical, _write_physical

_FIXTURE = Path(__file__).resolve().parents[1].parent / "dataset" / "elf_vm_arith_x86_64"


def test_write_physical_round_trips_blob_larger_than_r2_command_buffer(tmp_path: Path) -> None:
    if not _FIXTURE.exists():
        import pytest

        pytest.skip(f"fixture missing: {_FIXTURE}")

    target = tmp_path / "target"
    shutil.copy(_FIXTURE, target)
    # Comfortably past one r2 command buffer (~2 KiB of blob = ~4 KiB of hex).
    blob = bytes((i * 31 + 7) & 0xFF for i in range(8192))

    binary = Binary(str(target), writable=True)
    binary.open()
    try:
        offset = _file_size(binary)
        _write_physical(binary, offset, blob)
        readback = _read_physical(binary, offset, len(blob))
    finally:
        binary.close()

    assert readback == blob
