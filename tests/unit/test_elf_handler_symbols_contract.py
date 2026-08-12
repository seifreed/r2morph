from pathlib import Path

from r2morph.platform.elf_handler_symbols import collect_symbol_tables

_ELF_FIXTURE = Path(__file__).parents[2] / "fixtures" / "dataset" / "elf_x86_64"


def test_elf_handler_symbols_reads_real_symbol_table() -> None:
    tables = collect_symbol_tables(_ELF_FIXTURE)

    assert any(symbol["name"] == "_start" for symbol in tables["symtab"])
