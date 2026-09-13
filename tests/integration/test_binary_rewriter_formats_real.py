from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter import BinaryFormat, BinaryRewriter
from tests.utils.assertions import expect


@pytest.mark.parametrize(
    "binary_path, expected_format",
    [
        (Path("fixtures/dataset/elf_x86_64"), BinaryFormat.ELF),
        (Path("fixtures/dataset/pe_x86_64.exe"), BinaryFormat.PE),
        (Path("fixtures/dataset/macho_arm64"), BinaryFormat.MACHO),
    ],
)
def test_binary_rewriter_analyze_binary_formats(binary_path: Path, expected_format: BinaryFormat):
    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")

        rewriter = BinaryRewriter(bin_obj)
        expect(not (rewriter._analyze_binary() is not True))
        expect(rewriter.binary_format == expected_format)
        expect(rewriter.sections)

        expect(not (rewriter._initialize_codegen() is not True))


def test_binary_rewriter_rewrite_no_patches(tmp_path: Path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    output_path = tmp_path / "elf_rewritten"

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        bin_obj.filepath = str(binary_path)

        rewriter = BinaryRewriter(bin_obj)
        result = rewriter.rewrite_binary(str(output_path), patches=[], preserve_original=False)

    expect(not (result.success is not True))
    expect(output_path.exists())
    expect(not (result.integrity_checks.get("file_exists") is not True))
    expect(not (result.integrity_checks.get("valid_pe_header") is not True))


@pytest.mark.parametrize(
    "binary_path, expected_format",
    [
        (Path("fixtures/dataset/elf_x86_64"), BinaryFormat.ELF),
        (Path("fixtures/dataset/pe_x86_64.exe"), BinaryFormat.PE),
        (Path("fixtures/dataset/macho_arm64"), BinaryFormat.MACHO),
    ],
)
def test_binary_rewriter_noop_preserves_real_format(
    tmp_path: Path, binary_path: Path, expected_format: BinaryFormat
) -> None:
    output_path = tmp_path / f"rewritten_{binary_path.name}"

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        bin_obj.filepath = str(binary_path)
        result = BinaryRewriter(bin_obj).rewrite_binary(str(output_path), patches=[], preserve_original=False)

    expect(result.success)
    with Binary(output_path) as rewritten:
        rewritten.analyze("aa")
        rewriter = BinaryRewriter(rewritten)
        expect(rewriter._analyze_binary())
        expect(rewriter.binary_format == expected_format)
