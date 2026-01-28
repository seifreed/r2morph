from r2morph.mutations.instruction_expansion import InstructionExpansionPass


def test_instruction_expansion_helpers():
    pass_obj = InstructionExpansionPass()

    expansions = pass_obj._match_expansion_pattern({"disasm": "inc eax"}, "x86")
    assert isinstance(expansions, list)
    assert expansions

    # Build instruction from pattern with a valid register
    pattern = ("inc", "reg")
    built = pass_obj._build_instruction_from_pattern(pattern, ["inc", "eax"])
    assert built == "inc eax"

    # Reject size specifier as register target
    invalid = pass_obj._build_instruction_from_pattern(("inc", "reg"), ["mov", "dword", "[rsp]", ",", "eax"])
    assert invalid is None

    size_increase = pass_obj._get_expansion_size_increase([("mov", "reg", "reg"), ("xor", "reg", "reg")])
    assert size_increase >= 0

    assert pass_obj._is_safe_to_expand({"type": "jmp"}, 100) is False
    assert pass_obj._is_safe_to_expand({"type": "ret"}, 100) is False
    assert pass_obj._is_safe_to_expand({"type": "mov"}, 2000) is False
    assert pass_obj._is_safe_to_expand({"type": "mov"}, 100) is True
