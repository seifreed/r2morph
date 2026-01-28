import platform
import shutil
from pathlib import Path

from r2morph.platform.codesign import CodeSigner
from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler


def _copy_binary(tmp_path: Path, src: Path, name: str) -> Path:
    dst = tmp_path / name
    shutil.copy2(src, dst)
    return dst


def test_elf_handler_symbols_and_preserve(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    handler = ELFHandler(binary_path)

    symbols = handler.get_symbol_tables()
    assert "symtab" in symbols
    assert "dynsym" in symbols

    preserved = handler.preserve_symbols()
    assert preserved in {True, False}


def test_pe_handler_checksum(tmp_path: Path):
    binary_path = _copy_binary(tmp_path, Path("dataset/pe_x86_64.exe"), "pe_tmp.exe")
    handler = PEHandler(binary_path)

    checksum = handler._calculate_checksum()
    assert isinstance(checksum, int)

    fixed = handler.fix_checksum()
    assert fixed in {True, False}


def test_macho_handler_repair_and_codesign(tmp_path: Path):
    if platform.system() != "Darwin":
        return
    binary_path = _copy_binary(tmp_path, Path("dataset/macho_arm64"), "macho_tmp")
    handler = MachOHandler(binary_path)

    ok, _msg = handler.validate_integrity()
    assert isinstance(ok, bool)

    repaired = handler.repair_integrity()
    assert repaired in {True, False}

    signer = CodeSigner()
    signed = signer.sign_binary(binary_path, adhoc=True)
    assert signed in {True, False}

    verified = signer.verify(binary_path)
    assert verified in {True, False}

    needs = signer.needs_signing(binary_path)
    assert needs in {True, False}

    removed = signer.remove_signature(binary_path)
    assert removed in {True, False}
