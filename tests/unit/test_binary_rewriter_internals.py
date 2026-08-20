from pathlib import Path

from r2morph.devirtualization.binary_rewriter import (
    BinaryFormat,
    BinaryRewriter,
    CodePatch,
    RewriteOperation,
)
from tests.utils.assertions import expect


def test_binary_rewriter_strategy_and_address_shifts():
    rewriter = BinaryRewriter()
    rewriter.patches = [
        CodePatch(
            address=0x2000,
            operation=RewriteOperation.INSTRUCTION_INSERT,
            original_bytes=b"",
            new_bytes=b"\x90" * 120,
            size_change=120,
        ),
        CodePatch(
            address=0x1000,
            operation=RewriteOperation.INSTRUCTION_REPLACE,
            original_bytes=b"\x90",
            new_bytes=b"\x90\x90",
            size_change=1,
        ),
    ]

    strategy = rewriter._plan_rewrite_strategy()
    expect(not (strategy["use_code_caves"] is not True))
    expect(not (strategy["requires_relocation_update"] is not True))
    expect([p.address for p in strategy["patch_order"]] == [4096, 8192])

    shifts = rewriter._calculate_address_shifts()
    expect(shifts[4096] == 0)
    expect(shifts[8192] == 1)


def test_binary_rewriter_integrity_checks_for_elf(tmp_path: Path):
    output_path = tmp_path / "sample_elf"
    output_path.write_bytes(b"\x7fELF" + b"\x00" * 60)

    rewriter = BinaryRewriter()
    rewriter.binary_format = BinaryFormat.ELF

    checks = rewriter._perform_integrity_checks(str(output_path))
    expect(not (checks["file_exists"] is not True))
    expect(not (checks["valid_pe_header"] is not True))
    # The three checks below are not yet implemented and must stay False
    # until real parsers populate them. Asserting True here would
    # re-enshrine a placeholder that lied about binary integrity.
    expect(not (checks["imports_intact"] is not False))
    expect(not (checks["exports_intact"] is not False))
    expect(not (checks["entry_point_valid"] is not False))


def test_binary_rewriter_address_validation_and_stats():
    rewriter = BinaryRewriter()
    rewriter.sections = {
        ".text": {"vaddr": 0x1000, "vsize": 0x200},
        ".data": {"vaddr": 0x3000, "vsize": 0x100},
    }

    expect(not (rewriter._is_valid_address(0x1100) is not True))
    expect(not (rewriter._is_valid_address(0x2200) is not False))

    rewriter.binary_format = BinaryFormat.ELF
    rewriter.arch = "x86"
    rewriter.bits = 64
    rewriter.patches = [
        CodePatch(
            address=0x1000,
            operation=RewriteOperation.INSTRUCTION_DELETE,
            original_bytes=b"\x90",
            new_bytes=b"",
            size_change=-1,
        )
    ]

    stats = rewriter.get_rewrite_statistics()
    expect(stats["total_patches"] == 1)
    expect(stats["binary_format"] == "elf")
    expect(not ("x86" not in stats["architecture"]))


def test_binary_rewriter_instruction_validation_accepts_basic_asm():
    rewriter = BinaryRewriter()
    expect(not (rewriter._validate_instructions(["nop", "ret"]) is not True))
