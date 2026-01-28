from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.manager import RelocationManager


def test_relocation_manager_space_and_shift(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "reloc_sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        sections = binary.get_sections()
        assert sections
        section = next((s for s in sections if s.get("vaddr")), sections[0])
        vaddr = int(section.get("vaddr", 0) or 0)
        assert vaddr > 0

        # Place a small NOP block to check space and shifting.
        binary.write_bytes(vaddr, b"\x90" * 8)

        manager = RelocationManager(binary)
        assert manager.calculate_space_needed(vaddr, 4) is True

        original_hex = binary.r2.cmd(f"p8 4 @ 0x{vaddr:x}")
        assert manager.shift_code_block(vaddr, 4, 4) is True

        shifted_hex = binary.r2.cmd(f"p8 4 @ 0x{vaddr + 4:x}")
        assert shifted_hex.strip().lower() == original_hex.strip().lower()

        manager.add_relocation(vaddr, vaddr + 4, 4, "move")
        assert manager.get_new_address(vaddr) == vaddr + 4
