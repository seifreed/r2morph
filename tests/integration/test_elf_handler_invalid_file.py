from pathlib import Path

from r2morph.platform.elf_handler import ELFHandler
from tests.utils.assertions import expect


def test_elf_handler_invalid_file(tmp_path: Path):
    fake = tmp_path / "not_elf.bin"
    fake.write_bytes(b"NOTELF")

    handler = ELFHandler(fake)
    expect(not (handler.is_elf() is not False))
    expect(not (handler.validate() is not False))
    expect(not (handler.get_entry_point() is not None))
    expect(handler.get_architecture() == {})
