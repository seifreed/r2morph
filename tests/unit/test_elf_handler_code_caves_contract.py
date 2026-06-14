from pathlib import Path

from r2morph.platform.elf_handler_code_caves import find_code_cave


def test_elf_handler_code_caves_contract(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.elf"
    binary_path.write_bytes(b"\x00" * 128)

    sections = [
        {"flags": 0x4, "size": 16, "offset": 0, "vaddr": 0x401000, "name": ".text"},
    ]

    assert find_code_cave(binary_path, sections, min_size=8) == 0x401000
