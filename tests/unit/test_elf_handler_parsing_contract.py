from pathlib import Path

from r2morph.platform.elf_handler_parsing import get_section_name, parse_elf_header, read_shstrtab


def test_get_section_name_contract() -> None:
    assert get_section_name(0, b"\x00.text\x00") == ""
    assert get_section_name(1, b"\x00.text\x00") == ".text"


def test_parse_elf_header_contract() -> None:
    header, is_64bit, is_little_endian = parse_elf_header(Path("dataset/elf_x86_64"))
    assert header is not None
    assert is_64bit is True
    assert is_little_endian is True
    assert header["e_phoff"] > 0


def test_read_shstrtab_contract(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00" * 128)

    header = {
        "e_shstrndx": 2,
        "e_shnum": 2,
        "e_shoff": 16,
        "e_shentsize": 16,
        "is_little_endian": True,
        "is_64bit": False,
    }

    with binary.open("rb") as f:
        assert read_shstrtab(f, header, binary.stat().st_size) == b""
