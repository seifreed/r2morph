from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter import (
    BinaryRewriter,
    RewriteOperation,
    BinaryFormat,
)


def test_binary_rewriter_basic_workflow(tmp_path):
    binary_path = Path("dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        bin_obj.filepath = str(binary_path)

        rewriter = BinaryRewriter(bin_obj)

        assert rewriter._analyze_binary() is True
        assert rewriter.binary_format in {BinaryFormat.ELF, BinaryFormat.UNKNOWN}
        assert rewriter._initialize_codegen() is True

        section = next(iter(rewriter.sections.values()))
        addr = section.get("vaddr", 0) + 1

        assert rewriter.add_patch(addr, ["nop"], RewriteOperation.INSTRUCTION_REPLACE) is True

        validation = rewriter._validate_patches()
        assert validation["valid"] is True

        strategy = rewriter._plan_rewrite_strategy()
        stats = rewriter._apply_patches(strategy)
        assert stats["patches_applied"] >= 1

        reloc_stats = rewriter._update_relocations()
        assert "updated" in reloc_stats

        rewriter._update_metadata()

        output_path = tmp_path / "rewritten_elf"
        assert rewriter._write_output_binary(str(output_path)) is True

        checks = rewriter._perform_integrity_checks(str(output_path))
        assert checks["file_exists"] is True

        summary = rewriter.get_rewrite_statistics()
        assert summary["sections"] >= 1
