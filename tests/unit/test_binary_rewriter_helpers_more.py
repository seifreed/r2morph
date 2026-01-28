from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter import BinaryRewriter, CodePatch, RewriteOperation, BinaryFormat


def test_binary_rewriter_helpers_with_real_binary(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        rewriter = BinaryRewriter(binary=bin_obj)
        assert rewriter._analyze_binary() is True

        # Validate address helpers
        assert rewriter.sections
        first_section = next(iter(rewriter.sections.values()))
        section_addr = first_section.get("vaddr", 0)
        section_size = first_section.get("vsize", 0)
        if section_addr and section_size:
            assert rewriter._is_valid_address(section_addr) is True
            assert rewriter._is_valid_address(section_addr + section_size + 0x1000) is False

            bytes_at = rewriter._get_bytes_at_address(section_addr, 4)
            assert isinstance(bytes_at, bytes)
            assert len(bytes_at) == 4

        # Assembly helpers when keystone is unavailable
        rewriter.ks = None
        assembled = rewriter._assemble_instructions(["nop", "nop"])
        assert isinstance(assembled, bytes)
        assert len(assembled) == 2
        assert rewriter._validate_instructions(["nop"]) is True

        # Address shift calculation with patches
        rewriter.patches = [
            CodePatch(address=0x1000, operation=RewriteOperation.INSTRUCTION_INSERT, original_bytes=b"", new_bytes=b"\x90", size_change=1),
            CodePatch(address=0x2000, operation=RewriteOperation.INSTRUCTION_DELETE, original_bytes=b"\x90", new_bytes=b"", size_change=-1),
        ]
        shifts = rewriter._calculate_address_shifts()
        assert shifts.get(0x1000) == 0
        assert shifts.get(0x2000) == 1

        # Integrity checks on a real file
        output_path = tmp_path / "elf_output"
        output_path.write_bytes(binary_path.read_bytes())
        rewriter.binary_format = BinaryFormat.ELF
        checks = rewriter._perform_integrity_checks(str(output_path))
        assert checks["file_exists"] is True
        assert checks["valid_pe_header"] is True
