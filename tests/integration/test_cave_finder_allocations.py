from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.cave_finder import CaveFinder


def test_cave_allocation_and_insertion_real(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    work_path = tmp_path / "cave_sample.bin"
    work_path.write_bytes(binary_path.read_bytes())

    with Binary(work_path, writable=True) as bin_obj:
        bin_obj.analyze()
        sections = bin_obj.get_sections()
        exec_sections = [
            section for section in sections if "x" in str(section.get("perm", "")).lower()
        ]
        assert exec_sections, "Expected at least one executable section"
        section = exec_sections[0]
        vaddr = int(section.get("vaddr", 0) or 0)
        assert vaddr > 0, "Executable section has invalid vaddr"

        # Create a deterministic cave to avoid skip paths.
        bin_obj.write_bytes(vaddr, b"\x90" * 32)

        finder = CaveFinder(bin_obj, min_size=8)
        caves = finder.find_caves()
        assert caves, "Expected caves after inserting NOPs"

        cave = finder.find_cave_for_size(8)
        assert cave is not None

        addr, size = finder.allocate_cave(cave, 4)
        assert size == 4
        assert addr > 0

        inserted = finder.insert_code_in_cave(b"\x90" * 4)
        assert inserted is not None
