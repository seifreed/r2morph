from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.reference_updater import ReferenceUpdater


def _find_rw_section(binary: Binary) -> int:
    sections = binary.r2.cmdj("iSj") or []
    for section in sections:
        perm = section.get("perm", "")
        vaddr = section.get("vaddr", 0)
        size = section.get("vsize", 0)
        name = (section.get("name", "") or "").lower()
        if ("w" in perm or "data" in name or "got" in name) and vaddr and size >= 16:
            return vaddr
    for section in sections:
        vaddr = section.get("vaddr", 0)
        size = section.get("vsize", 0)
        if vaddr and size >= 16:
            return vaddr
    return 0


def test_reference_updater_data_pointer_updates(tmp_path: Path):
    src = Path("dataset/macho_arm64")
    dst = tmp_path / "macho_ref_updater"
    dst.write_bytes(src.read_bytes())

    with Binary(dst, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        updater = ReferenceUpdater(bin_obj)

        ptr_addr = _find_rw_section(bin_obj)
        assert ptr_addr != 0

        old_value = 0x1122334455667788
        new_value = 0x8877665544332211

        bin_obj.write_bytes(ptr_addr, old_value.to_bytes(8, byteorder="little"))

        assert updater.update_data_pointer(ptr_addr, old_value, new_value) is True

        updated_hex = bin_obj.r2.cmd(f"p8 8 @ 0x{ptr_addr:x}")
        updated_value = int.from_bytes(bytes.fromhex(updated_hex.strip()), byteorder="little")
        assert updated_value == new_value

        assert updater.update_data_pointer(ptr_addr, old_value, new_value) is False
