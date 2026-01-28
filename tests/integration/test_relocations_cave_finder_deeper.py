import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.relocations.cave_finder import CaveFinder


def _copy_binary(tmp_path: Path, name: str) -> Path:
    src = Path("dataset/elf_x86_64")
    dst = tmp_path / name
    shutil.copy2(src, dst)
    return dst


def test_cave_finder_insertion(tmp_path: Path):
    binary_path = _copy_binary(tmp_path, "elf_caves")

    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        sections = bin_obj.get_sections()
        exec_section = next((s for s in sections if "x" in s.get("perm", "")), None)

        if exec_section:
            start = exec_section.get("vaddr", 0)
            bin_obj.write_bytes(start, b"\x90" * 16)

        finder = CaveFinder(bin_obj, min_size=8)
        caves = finder.find_caves(max_caves=10)
        assert isinstance(caves, list)

        if caves:
            cave = caves[0]
            addr, size = finder.allocate_cave(cave, min(4, cave.size))
            assert size > 0
            inserted = finder.insert_code_in_cave(b"\x90\x90")
            assert inserted is None or isinstance(inserted, int)
