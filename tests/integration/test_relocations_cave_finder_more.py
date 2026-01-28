from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.cave_finder import CaveFinder


def test_cave_finder_allocate_and_insert_real(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "elf_caves"
    temp_binary.write_bytes(binary_path.read_bytes())

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        finder = CaveFinder(bin_obj, min_size=8)
        caves = finder.find_caves(max_caves=10)

        if not caves:
            sections = bin_obj.get_sections()
            exec_sections = [
                section for section in sections if "x" in str(section.get("perm", ""))
            ]
            if exec_sections:
                section = max(
                    exec_sections,
                    key=lambda item: max(item.get("vsize", 0), item.get("size", 0)),
                )
                vaddr = section.get("vaddr", 0)
                vsize = section.get("vsize", 0) or section.get("size", 0)
                if vaddr and vsize >= finder.min_size:
                    bin_obj.write_bytes(
                        vaddr + vsize - finder.min_size, b"\x00" * finder.min_size
                    )
                    caves = finder.find_caves(max_caves=10)

        assert caves, "Expected to find or create at least one cave"

        cave = finder.find_cave_for_size(4)
        assert cave is not None

        addr, size = finder.allocate_cave(cave, 4)
        assert size == 4

        inserted = finder.insert_code_in_cave(b"\x90\x90\x90\x90")
        assert inserted is not None
