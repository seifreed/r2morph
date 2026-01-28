from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.detection.pattern_matcher import PatternMatcher


def test_pattern_matcher_search_strings_and_patterns():
    binary_path = Path("dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        matcher = PatternMatcher(bin_obj)

        raw_strings = bin_obj.r2.cmd("izz") or ""
        sample_term = ""
        for token in raw_strings.split():
            if token.isascii() and token:
                sample_term = token
                break

        search_terms = [sample_term] if sample_term else []
        search_terms.append("unlikely_string_token_12345")
        results = matcher.search_strings(search_terms, case_sensitive=False)
        assert results["unlikely_string_token_12345"] is False
        if sample_term:
            assert results[sample_term] is True

        entry = bin_obj.r2.cmdj("iej") or []
        entry_addr = entry[0].get("vaddr", 0) if entry else 0
        bytes_hex = bin_obj.r2.cmd(f"p8 4 @ 0x{entry_addr:x}").strip()
        pattern = bytes.fromhex(bytes_hex) if bytes_hex else b""
        if pattern:
            matches = matcher.find_patterns([pattern])
            assert isinstance(matches, dict)


def test_pattern_matcher_import_hiding_and_string_encryption():
    binary_path = Path("dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        matcher = PatternMatcher(bin_obj)
        import_hiding = matcher._detect_import_hiding()
        assert isinstance(import_hiding, bool)

        string_encryption = matcher._detect_string_encryption()
        assert string_encryption in (True, False)


def test_pattern_matcher_error_paths_on_closed_binary(tmp_path):
    binary_path = Path("dataset/elf_x86_64")
    bin_obj = Binary(binary_path)
    bin_obj.open()
    matcher = PatternMatcher(bin_obj)
    bin_obj.close()

    results = matcher.search_strings(["test"], case_sensitive=False)
    assert results["test"] is False
