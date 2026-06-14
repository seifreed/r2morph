from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.detection.pattern_matcher_search import find_patterns, search_strings


def test_pattern_matcher_search_helpers_work_on_real_binary():
    binary_path = Path("dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        raw_strings = bin_obj.r2.cmd("izz") or ""
        sample_term = ""
        for token in raw_strings.split():
            if token.isascii() and token:
                sample_term = token
                break

        terms = [sample_term] if sample_term else []
        terms.append("unlikely_string_token_12345")
        string_results = search_strings(bin_obj, terms, case_sensitive=False)
        assert string_results["unlikely_string_token_12345"] is False
        if sample_term:
            assert string_results[sample_term] is True

        entry = bin_obj.r2.cmdj("iej") or []
        entry_addr = entry[0].get("vaddr", 0) if entry else 0
        bytes_hex = bin_obj.r2.cmd(f"p8 4 @ 0x{entry_addr:x}").strip()
        pattern = bytes.fromhex(bytes_hex) if bytes_hex else b""
        if pattern:
            matches = find_patterns(bin_obj, [pattern])
            assert isinstance(matches, dict)
