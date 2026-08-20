from pathlib import Path

from r2morph.platform.elf_handler_validation import validate_elf_file_structure
from tests.utils.assertions import expect


def test_validate_elf_file_structure_contract(tmp_path: Path) -> None:
    binary = tmp_path / "sample.elf"
    binary.write_bytes(b"\x00" * 256)

    header = {
        "e_shentsize": 1,
        "e_shnum": 4,
        "e_shoff": 32,
        "e_phentsize": 1,
        "e_phnum": 4,
        "e_phoff": 64,
    }

    expect(not (validate_elf_file_structure(binary, header) is not True))


def test_validate_elf_file_structure_rejects_out_of_bounds(tmp_path: Path) -> None:
    binary = tmp_path / "sample.elf"
    binary.write_bytes(b"\x00" * 64)

    header = {
        "e_shentsize": 16,
        "e_shnum": 8,
        "e_shoff": 48,
        "e_phentsize": 1,
        "e_phnum": 1,
        "e_phoff": 8,
    }

    expect(not (validate_elf_file_structure(binary, header) is not False))
