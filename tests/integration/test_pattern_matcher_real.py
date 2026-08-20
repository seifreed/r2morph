from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.pattern_matcher import PatternMatcher
from tests.utils.assertions import expect


def test_pattern_matcher_scan_and_searches() -> None:
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        matcher = PatternMatcher(bin_obj)

        result = matcher.scan()
        expect(isinstance(result.anti_debug_detected, bool))
        expect(isinstance(result.anti_vm_detected, bool))
        expect(isinstance(result.string_encryption_detected, bool))
        expect(isinstance(result.import_hiding_detected, bool))

        found = matcher.search_strings(["ELF", "libc", "definitely_not_here"])
        expect(set(found.keys()) == {"ELF", "libc", "definitely_not_here"})

        data = binary_path.read_bytes()
        pattern = data[:4]
        matches = matcher.find_patterns([pattern])
        expect(isinstance(matches, dict))
        expect(not (pattern in matches and not (all(isinstance(addr, int) for addr in matches[pattern]))))
