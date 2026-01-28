from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.pattern_matcher import PatternMatcher


def test_pattern_matcher_find_patterns_and_strings(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "pattern_sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        binary.r2.cmd("e search.in=io.maps")

        sections = binary.get_sections()
        assert sections
        section = next((s for s in sections if s.get("vaddr")), sections[0])
        vaddr = int(section.get("vaddr", 0) or 0)
        assert vaddr > 0

        marker = b"R2MORPH"
        marker_string = b"R2MORPH_TEST_STRING"
        binary.write_bytes(vaddr, marker + marker_string + b"\x00")

        matcher = PatternMatcher(binary)
        found = matcher.find_patterns([marker])
        assert marker in found
        assert vaddr in found[marker]

        string_results = matcher.search_strings([marker_string.decode()], case_sensitive=False)
        assert string_results[marker_string.decode()] is True

        scan = matcher.scan()
        assert isinstance(scan.anti_debug_detected, bool)
        assert 0.0 <= scan.anti_debug_confidence <= 1.0
        assert isinstance(scan.anti_vm_detected, bool)
        assert 0.0 <= scan.anti_vm_confidence <= 1.0
