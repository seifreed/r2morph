from pathlib import Path

from r2morph.platform.elf_handler_code_caves import find_code_cave
from tests.utils.assertions import expect

_EXPECTED_FIND_CODE_CAVE_BINARY_PATH_SECTIONS_MIN_SIZE__4198400 = 0x401000


def test_elf_handler_code_caves_contract(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.elf"
    binary_path.write_bytes(b"\x00" * 128)

    sections = [
        {"flags": 0x4, "size": 16, "offset": 0, "vaddr": 0x401000, "name": ".text"},
    ]

    expect(
        find_code_cave(binary_path, sections, min_size=8)
        == _EXPECTED_FIND_CODE_CAVE_BINARY_PATH_SECTIONS_MIN_SIZE__4198400
    )
