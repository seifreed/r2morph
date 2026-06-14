from r2morph.mutations.instruction_substitution_helpers import (
    get_equivalents,
    init_substitution_rules,
    normalize_instruction,
    select_candidates,
)


class _Binary:
    def get_function_disasm(self, addr: int):
        if addr == 0x1000:
            return [{"disasm": "xor eax, eax"}]
        if addr == 0x2000:
            return [{"disasm": "mov rax, rbx"}]
        raise ValueError(addr)


def test_instruction_substitution_helpers_cover_the_core_paths() -> None:
    equivalence_groups = {"x86": [["xor eax, eax", "sub eax, eax"]]}
    pattern_to_group = {"x86": {"xor eax, eax": 0}}

    assert normalize_instruction("  XOR   EAX, EAX ") == "xor eax, eax"
    original, equivalents, group_idx = get_equivalents(
        {"disasm": "xor eax, eax"}, "x86", pattern_to_group, equivalence_groups
    )
    assert original == "xor eax, eax"
    assert equivalents == ["xor eax, eax", "sub eax, eax"]
    assert group_idx == 0

    binary = _Binary()
    functions = [
        {"name": "main", "offset": 0x1000, "size": 64},
        {"name": "tiny", "offset": 0x2000, "size": 4},
    ]
    selected = select_candidates(binary, functions, "x86", pattern_to_group, equivalence_groups)
    assert selected[0][0]["name"] == "main"

    loaded_groups, loaded_patterns = init_substitution_rules()
    assert "x86" in loaded_groups
    assert "x86" in loaded_patterns
