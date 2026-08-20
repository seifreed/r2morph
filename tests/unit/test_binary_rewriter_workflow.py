from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter import (
    BinaryFormat,
    BinaryRewriter,
    RewriteOperation,
)
from tests.utils.assertions import expect


def test_binary_rewriter_basic_workflow(tmp_path):
    binary_path = Path("fixtures/dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        bin_obj.filepath = str(binary_path)

        rewriter = BinaryRewriter(bin_obj)

        expect(not (rewriter._analyze_binary() is not True))
        expect(not (rewriter.binary_format not in {BinaryFormat.ELF, BinaryFormat.UNKNOWN}))
        expect(not (rewriter._initialize_codegen() is not True))

        section = next(iter(rewriter.sections.values()))
        addr = section.get("vaddr", 0) + 1

        expect(not (rewriter.add_patch(addr, ["nop"], RewriteOperation.INSTRUCTION_REPLACE) is not True))

        validation = rewriter._validate_patches()
        expect(not (validation["valid"] is not True))

        strategy = rewriter._plan_rewrite_strategy()
        stats = rewriter._apply_patches(strategy)
        expect(not (stats["patches_applied"] < 1))

        reloc_stats = rewriter._update_relocations()
        expect(not ("updated" not in reloc_stats))

        rewriter._update_metadata()

        output_path = tmp_path / "rewritten_elf"
        expect(not (rewriter._write_output_binary(str(output_path)) is not True))

        checks = rewriter._perform_integrity_checks(str(output_path))
        expect(not (checks["file_exists"] is not True))

        summary = rewriter.get_rewrite_statistics()
        expect(not (summary["sections"] < 1))
