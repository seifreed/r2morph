from pathlib import Path

from r2morph.platform.elf_handler_tables import collect_sections, collect_segments


def test_elf_handler_tables_contract(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.elf"
    binary_path.write_bytes(b"\x7fELF" + b"\x00" * 128)

    header = {
        "is_64bit": True,
        "is_little_endian": True,
        "e_shoff": 0,
        "e_shnum": 0,
        "e_shentsize": 64,
        "e_shstrndx": 0,
        "e_phoff": 0,
        "e_phnum": 0,
        "e_phentsize": 56,
    }

    with binary_path.open("rb") as f:
        assert collect_sections(binary_path, header, f) == []
        f.seek(0)
        assert collect_segments(binary_path, header, f) == []
