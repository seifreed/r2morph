from r2morph.mutations.instruction_expansion import InstructionExpansionPass


def test_instruction_expansion_helpers():
    pass_obj = InstructionExpansionPass()

    # inc/dec rules were removed (flag-unsafe: inc preserves CF, add modifies it)
    expansions = pass_obj._match_expansion_pattern({"disasm": "inc eax"}, "x86")
    assert isinstance(expansions, list)
    assert not expansions  # No expansion for inc (flag-unsafe)

    # Test flag-safe expansion: imul reg, 2 → shl reg, 1
    expansions = pass_obj._match_expansion_pattern({"disasm": "imul eax, 2"}, "x86")
    assert isinstance(expansions, list)

    # Build instruction from pattern with a valid register
    pattern = ("shl", "reg", "1")
    built = pass_obj._build_instruction_from_pattern(pattern, ["shl", "eax", "1"])
    assert built == "shl eax, 1"

    # Reject size specifier as register target
    invalid = pass_obj._build_instruction_from_pattern(("inc", "reg"), ["mov", "dword", "[rsp]", ",", "eax"])
    assert invalid is None

    size_increase = pass_obj._get_expansion_size_increase([("mov", "reg", "reg"), ("xor", "reg", "reg")])
    assert size_increase >= 0

    assert pass_obj._is_safe_to_expand({"type": "jmp"}, 100) is False
    assert pass_obj._is_safe_to_expand({"type": "ret"}, 100) is False
    assert pass_obj._is_safe_to_expand({"type": "mov"}, 2000) is False
    assert pass_obj._is_safe_to_expand({"type": "mov"}, 100) is True
