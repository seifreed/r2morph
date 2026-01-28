from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.pattern_matcher import PatternMatcher, PatternMatchResult
from r2morph.detection.similarity_hasher import SimilarityHasher


def test_similarity_hasher_compare_files_real(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    original = tmp_path / "orig_elf"
    modified = tmp_path / "modified_elf"
    original.write_bytes(binary_path.read_bytes())
    modified.write_bytes(binary_path.read_bytes())

    # Flip one byte to change similarity
    data = bytearray(modified.read_bytes())
    if data:
        data[0] ^= 0xFF
    modified.write_bytes(bytes(data))

    hasher = SimilarityHasher()
    result = hasher.compare_files(original, modified)

    assert "byte_similarity" in result
    assert 0.0 <= result["byte_similarity"] <= 100.0
    assert result["byte_similarity"] < 100.0


def test_pattern_matcher_scan_and_search_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        matcher = PatternMatcher(bin_obj)
        result = matcher.scan()

        assert isinstance(result, PatternMatchResult)
        assert 0.0 <= result.anti_debug_confidence <= 1.0
        assert 0.0 <= result.anti_vm_confidence <= 1.0
        assert isinstance(result.anti_debug_apis, list)
        assert isinstance(result.anti_vm_artifacts, list)

        # String search returns booleans per term
        terms = ["this_string_should_not_exist", "ELF"]
        found = matcher.search_strings(terms, case_sensitive=False)
        assert set(found.keys()) == set(terms)
        assert all(isinstance(val, bool) for val in found.values())

        # Byte pattern search for ELF magic
        patterns = [b"\x7fELF"]
        matches = matcher.find_patterns(patterns)
        if matches:
            assert patterns[0] in matches
            assert matches[patterns[0]]
