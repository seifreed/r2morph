from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.reference_updater import ReferenceUpdater


def test_reference_updater_jump_and_pointer(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "ref_sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        sections = binary.get_sections()
        assert sections
        section = next((s for s in sections if s.get("vaddr")), sections[0])
        vaddr = int(section.get("vaddr", 0) or 0)
        assert vaddr > 0

        old_target = vaddr + 0x200
        new_target = vaddr + 0x210
        jump_bytes = binary.assemble(f"je 0x{old_target:x}")
        if not jump_bytes:
            pytest.skip("Assembler unavailable for jump instruction")
        binary.write_bytes(vaddr, jump_bytes + b"\x90" * 16)

        updater = ReferenceUpdater(binary)
        assert updater.update_jump_target(vaddr, old_target, new_target) is True

        arch_info = binary.get_arch_info()
        ptr_size = arch_info["bits"] // 8
        data_section = next((s for s in sections if s.get("vaddr") and s.get("paddr")), None)
        assert data_section is not None
        section_vaddr = int(data_section.get("vaddr", 0) or 0)
        section_paddr = int(data_section.get("paddr", 0) or 0)
        section_size = int(data_section.get("size") or data_section.get("vsize") or 0)
        assert section_vaddr > 0
        assert section_size > ptr_size

        ptr_addr = section_vaddr + min(0x40, section_size - ptr_size)
        current_hex = binary.r2.cmd(f"p8 {ptr_size} @ 0x{ptr_addr:x}")
        current_value = int.from_bytes(bytes.fromhex(current_hex.strip()), byteorder="little")
        new_ptr = (current_value + 0x10) & ((1 << (ptr_size * 8)) - 1)
        assert updater.update_data_pointer(ptr_addr, current_value, new_ptr) is True

        physical_offset = section_paddr + (ptr_addr - section_vaddr)
        with open(work_path, "rb") as handle:
            handle.seek(physical_offset)
            updated_bytes = handle.read(ptr_size)
        updated_value = int.from_bytes(updated_bytes, byteorder="little")
        assert updated_value == new_ptr
