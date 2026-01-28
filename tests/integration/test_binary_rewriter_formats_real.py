from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter import BinaryRewriter, BinaryFormat


@pytest.mark.parametrize(
    "binary_path, expected_format",
    [
        (Path("dataset/elf_x86_64"), BinaryFormat.ELF),
        (Path("dataset/pe_x86_64.exe"), BinaryFormat.PE),
        (Path("dataset/macho_arm64"), BinaryFormat.MACHO),
    ],
)
def test_binary_rewriter_analyze_binary_formats(binary_path: Path, expected_format: BinaryFormat):
    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")

        rewriter = BinaryRewriter(bin_obj)
        assert rewriter._analyze_binary() is True
        assert rewriter.binary_format == expected_format
        assert rewriter.sections

        assert rewriter._initialize_codegen() is True


def test_binary_rewriter_rewrite_no_patches(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    output_path = tmp_path / "elf_rewritten"

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        bin_obj.filepath = str(binary_path)

        rewriter = BinaryRewriter(bin_obj)
        result = rewriter.rewrite_binary(str(output_path), patches=[], preserve_original=False)

    assert result.success is True
    assert output_path.exists()
    assert result.integrity_checks.get("file_exists") is True
    assert result.integrity_checks.get("valid_pe_header") is True
