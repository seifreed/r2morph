from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter import BinaryRewriter, CodePatch, RewriteOperation, RelocationEntry


@pytest.mark.parametrize(
    "binary_path",
    [
        Path("dataset/pe_x86_64.exe"),
        Path("dataset/macho_arm64"),
    ],
)
def test_binary_rewriter_metadata_updates(binary_path: Path, tmp_path: Path):
    if not binary_path.exists():
        pytest.skip("Binary not available")

    output_path = tmp_path / f"{binary_path.name}.rewritten"

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        bin_obj.filepath = str(binary_path)

        rewriter = BinaryRewriter(bin_obj)
        result = rewriter.rewrite_binary(str(output_path), patches=[], preserve_original=False)

    assert result.success is True
    assert output_path.exists()
    assert result.integrity_checks.get("file_exists") is True


def test_binary_rewriter_relocation_updates(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        rewriter = BinaryRewriter(bin_obj)
        assert rewriter._analyze_binary() is True

        rewriter.relocations = [
            RelocationEntry(address=0x1000, target=0x2000, reloc_type="REL"),
            RelocationEntry(address=0x3000, target=0x4000, reloc_type="REL"),
        ]
        rewriter.patches = [
            CodePatch(address=0x1000, operation=RewriteOperation.INSTRUCTION_INSERT, original_bytes=b"", new_bytes=b"\x90", size_change=4),
        ]

        stats = rewriter._update_relocations()
        assert stats["updated"] == 1
        assert rewriter.relocations[0].target == 0x2000
