from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from tests.utils.assertions import expect


def test_instruction_expansion_helpers():
    pass_obj = InstructionExpansionPass()

    # inc/dec rules were removed (flag-unsafe: inc preserves CF, add modifies it)
    expansions = pass_obj._match_expansion_pattern({"disasm": "inc eax"}, "x86")
    expect(isinstance(expansions, list))
    expect(not (expansions))

    # Test flag-safe expansion: imul reg, 2 → shl reg, 1
    expansions = pass_obj._match_expansion_pattern({"disasm": "imul eax, 2"}, "x86")
    expect(isinstance(expansions, list))

    # Build instruction from pattern with a valid register
    pattern = ("shl", "reg", "1")
    built = pass_obj._build_instruction_from_pattern(pattern, ["shl", "eax", "1"])
    expect(built == "shl eax, 1")

    # Reject size specifier as register target
    invalid = pass_obj._build_instruction_from_pattern(("inc", "reg"), ["mov", "dword", "[rsp]", ",", "eax"])
    expect(not (invalid is not None))

    size_increase = pass_obj._get_expansion_size_increase([("mov", "reg", "reg"), ("xor", "reg", "reg")])
    expect(not (size_increase < 0))

    expect(not (pass_obj._is_safe_to_expand({"type": "jmp"}, 100) is not False))
    expect(not (pass_obj._is_safe_to_expand({"type": "ret"}, 100) is not False))
    expect(not (pass_obj._is_safe_to_expand({"type": "mov"}, 2000) is not False))
    expect(not (pass_obj._is_safe_to_expand({"type": "mov"}, 100) is not True))
