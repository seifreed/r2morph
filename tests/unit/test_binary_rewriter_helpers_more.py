from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter import BinaryFormat, BinaryRewriter, CodePatch, RewriteOperation
from tests.utils.assertions import expect

_EXPECTED_LEN_ASSEMBLED_2 = 2
_EXPECTED_LEN_BYTES_AT_4 = 4


def test_binary_rewriter_helpers_with_real_binary(tmp_path: Path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        rewriter = BinaryRewriter(binary=bin_obj)
        expect(not (rewriter._analyze_binary() is not True))

        # Validate address helpers
        expect(rewriter.sections)
        first_section = next(iter(rewriter.sections.values()))
        section_addr = first_section.get("vaddr", 0)
        section_size = first_section.get("vsize", 0)
        if section_addr and section_size:
            expect(not (rewriter._is_valid_address(section_addr) is not True))
            expect(not (rewriter._is_valid_address(section_addr + section_size + 0x1000) is not False))

            bytes_at = rewriter._get_bytes_at_address(section_addr, 4)
            expect(isinstance(bytes_at, bytes))
            expect(len(bytes_at) == _EXPECTED_LEN_BYTES_AT_4)

        # Assembly helpers when keystone is unavailable
        rewriter.ks = None
        assembled = rewriter._assemble_instructions(["nop", "nop"])
        expect(isinstance(assembled, bytes))
        expect(len(assembled) == _EXPECTED_LEN_ASSEMBLED_2)
        expect(not (rewriter._validate_instructions(["nop"]) is not True))

        # Address shift calculation with patches
        rewriter.patches = [
            CodePatch(
                address=0x1000,
                operation=RewriteOperation.INSTRUCTION_INSERT,
                original_bytes=b"",
                new_bytes=b"\x90",
                size_change=1,
            ),
            CodePatch(
                address=0x2000,
                operation=RewriteOperation.INSTRUCTION_DELETE,
                original_bytes=b"\x90",
                new_bytes=b"",
                size_change=-1,
            ),
        ]
        shifts = rewriter._calculate_address_shifts()
        expect(shifts.get(4096) == 0)
        expect(shifts.get(8192) == 1)

        # Integrity checks on a real file
        output_path = tmp_path / "elf_output"
        output_path.write_bytes(binary_path.read_bytes())
        rewriter.binary_format = BinaryFormat.ELF
        checks = rewriter._perform_integrity_checks(str(output_path))
        expect(not (checks["file_exists"] is not True))
        expect(not (checks["valid_pe_header"] is not True))
