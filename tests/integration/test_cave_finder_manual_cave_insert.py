from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.cave_finder import CaveFinder, CodeCave
from tests.utils.assertions import expect

_EXPECTED_FINDER_CAVES_0_SIZE_8 = 8
_EXPECTED_SIZE_8 = 8


def test_cave_finder_manual_insert_and_allocate(tmp_path: Path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    writable_path = tmp_path / "elf_x86_64_copy"
    writable_path.write_bytes(binary_path.read_bytes())

    with Binary(writable_path, writable=True) as bin_obj:
        bin_obj.analyze()

        sections = bin_obj.get_sections()
        exec_section = next(
            (sec for sec in sections if "x" in sec.get("perm", "").lower()),
            None,
        )
        if exec_section is None:
            pytest.skip("No executable section found")

        section_name = exec_section.get("name", "unknown")
        section_addr = exec_section.get("vaddr", 0)
        if section_addr == 0:
            pytest.skip("Executable section missing virtual address")

        finder = CaveFinder(bin_obj, min_size=4)
        cave = CodeCave(
            address=section_addr + 0x10,
            size=16,
            section=section_name,
            is_executable=True,
        )
        finder.caves = [cave]

        addr, size = finder.allocate_cave(cave, 8)
        expect(size == _EXPECTED_SIZE_8)
        expect(addr == section_addr + 16)
        # allocate_cave replaces the original cave with a smaller remainder
        expect(len(finder.caves) == 1)
        expect(finder.caves[0].size == _EXPECTED_FINDER_CAVES_0_SIZE_8)

        inserted_addr = finder.insert_code_in_cave(b"\x90" * 4, preferred_section=section_name)
        # insert_code_in_cave may return None when the binary's r2 session
        # cannot resolve the physical offset for the cave address
        expect(not (inserted_addr is not None and inserted_addr < section_addr))
