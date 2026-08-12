from pathlib import Path

from r2morph.platform.elf_handler_symbol_preservation import preserve_symbols

_ELF_FIXTURE = Path(__file__).parents[2] / "dataset" / "elf_x86_64"


def test_elf_handler_symbol_preservation_accepts_real_elf() -> None:
    assert preserve_symbols(_ELF_FIXTURE) is True
