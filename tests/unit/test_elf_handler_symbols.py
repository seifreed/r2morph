"""Characterization of ELFHandler.get_symbol_tables on a real 64-bit ELF.

Pins the exact symbol dicts (static + dynamic) against dataset/elf_x86_64 so
the duplicated symtab/dynsym collection loops can be unified without changing
observable output. No mocks (CLAUDE.md sec.4): a real handler parses a real
binary via lief, which is skipped when unavailable.
"""

import importlib.util
from pathlib import Path

import pytest

from r2morph.platform.elf_handler import ELFHandler

_HAS_LIEF = importlib.util.find_spec("lief") is not None


@pytest.mark.skipif(not _HAS_LIEF, reason="lief not available")
def test_get_symbol_tables_exact_real_elf64() -> None:
    handler = ELFHandler(Path("dataset/elf_x86_64"))

    result = handler.get_symbol_tables()

    assert result == {
        "symtab": [
            {
                "name": "",
                "value": 0,
                "size": 0,
                "type": "NOTYPE",
                "binding": "LOCAL",
                "visibility": "DEFAULT",
                "shndx": 0,
            },
            {
                "name": "_start",
                "value": 2101536,
                "size": 0,
                "type": "NOTYPE",
                "binding": "GLOBAL",
                "visibility": "DEFAULT",
                "shndx": 1,
            },
        ],
        "dynsym": [],
    }
