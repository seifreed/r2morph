from r2morph.mutations.instruction_expansion_helpers import (
    build_instruction_from_pattern,
    get_expansion_size_increase,
    is_safe_to_expand,
    match_expansion_pattern,
)


def test_instruction_expansion_helpers_cover_core_paths() -> None:
    expansions = match_expansion_pattern({"disasm": "imul eax, 2"}, "x86")
    assert expansions

    built = build_instruction_from_pattern(("shl", "reg", "1"), ["shl", "eax", "1"])
    assert built == "shl eax, 1"

    invalid = build_instruction_from_pattern(("inc", "reg"), ["mov", "dword", "[rsp]", ",", "eax"])
    assert invalid is None

    size_increase = get_expansion_size_increase([("mov", "reg", "reg"), ("xor", "reg", "reg")])
    assert size_increase >= 0

    assert is_safe_to_expand({"type": "jmp"}, 100) is False
    assert is_safe_to_expand({"type": "mov"}, 2000) is False
    assert is_safe_to_expand({"type": "mov"}, 100) is True
