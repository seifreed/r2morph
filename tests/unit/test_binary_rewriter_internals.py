from pathlib import Path

from r2morph.devirtualization.binary_rewriter import (
    BinaryRewriter,
    CodePatch,
    RewriteOperation,
    BinaryFormat,
)


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
    assert strategy["use_code_caves"] is True
    assert strategy["requires_relocation_update"] is True
    assert [p.address for p in strategy["patch_order"]] == [0x1000, 0x2000]

    shifts = rewriter._calculate_address_shifts()
    assert shifts[0x1000] == 0
    assert shifts[0x2000] == 1


def test_binary_rewriter_integrity_checks_for_elf(tmp_path: Path):
    output_path = tmp_path / "sample_elf"
    output_path.write_bytes(b"\x7fELF" + b"\x00" * 60)

    rewriter = BinaryRewriter()
    rewriter.binary_format = BinaryFormat.ELF

    checks = rewriter._perform_integrity_checks(str(output_path))
    assert checks["file_exists"] is True
    assert checks["valid_pe_header"] is True
    assert checks["imports_intact"] is True
    assert checks["exports_intact"] is True
    assert checks["entry_point_valid"] is True


def test_binary_rewriter_address_validation_and_stats():
    rewriter = BinaryRewriter()
    rewriter.sections = {
        ".text": {"vaddr": 0x1000, "vsize": 0x200},
        ".data": {"vaddr": 0x3000, "vsize": 0x100},
    }

    assert rewriter._is_valid_address(0x1100) is True
    assert rewriter._is_valid_address(0x2200) is False

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
    assert stats["total_patches"] == 1
    assert stats["binary_format"] == "elf"
    assert "x86" in stats["architecture"]


def test_binary_rewriter_instruction_validation_accepts_basic_asm():
    rewriter = BinaryRewriter()
    assert rewriter._validate_instructions(["nop", "ret"]) is True
