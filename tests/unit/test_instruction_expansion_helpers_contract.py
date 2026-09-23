from r2morph.mutations.instruction_expansion_helpers import (
    build_instruction_from_pattern,
    get_expansion_size_increase,
    is_safe_to_expand,
    match_expansion_pattern,
)
from tests.utils.assertions import expect


def test_instruction_expansion_helpers_cover_core_paths() -> None:
    expansions = match_expansion_pattern({"disasm": "imul eax, 2"}, "x86")
    expect(expansions)

    built = build_instruction_from_pattern(("shl", "reg", "1"), ["shl", "eax", "1"])
    expect(built == "shl eax, 1")

    invalid = build_instruction_from_pattern(("inc", "reg"), ["mov", "dword", "[rsp]", ",", "eax"])
    expect(not (invalid is not None))

    size_increase = get_expansion_size_increase([("mov", "reg", "reg"), ("xor", "reg", "reg")])
    expect(not (size_increase < 0))

    expect(not (is_safe_to_expand({"type": "jmp"}, 100) is not False))
    expect(not (is_safe_to_expand({"type": "mov"}, 2000) is not False))
    expect(not (is_safe_to_expand({"type": "mov"}, 100) is not True))


def test_arm_zero_expansion_does_not_match_nonzero_immediate() -> None:
    expect(not match_expansion_pattern({"disasm": "mov r2, 0x14"}, "arm"))


def test_arm_zero_expansion_matches_zero_immediate() -> None:
    expect(match_expansion_pattern({"disasm": "mov r2, 0"}, "arm"))
