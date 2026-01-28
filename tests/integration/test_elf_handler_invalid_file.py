from pathlib import Path

from r2morph.platform.elf_handler import ELFHandler


def test_elf_handler_invalid_file(tmp_path: Path):
    fake = tmp_path / "not_elf.bin"
    fake.write_bytes(b"NOTELF")

    handler = ELFHandler(fake)
    assert handler.is_elf() is False
    assert handler.validate() is False
    assert handler.get_entry_point() is None
    assert handler.get_architecture() == {}
