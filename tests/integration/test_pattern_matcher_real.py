from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.pattern_matcher import PatternMatcher


def test_pattern_matcher_scan_and_searches() -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        matcher = PatternMatcher(bin_obj)

        result = matcher.scan()
        assert isinstance(result.anti_debug_detected, bool)
        assert isinstance(result.anti_vm_detected, bool)
        assert isinstance(result.string_encryption_detected, bool)
        assert isinstance(result.import_hiding_detected, bool)

        found = matcher.search_strings(["ELF", "libc", "definitely_not_here"])
        assert set(found.keys()) == {"ELF", "libc", "definitely_not_here"}

        data = binary_path.read_bytes()
        pattern = data[:4]
        matches = matcher.find_patterns([pattern])
        assert isinstance(matches, dict)
        if pattern in matches:
            assert all(isinstance(addr, int) for addr in matches[pattern])
