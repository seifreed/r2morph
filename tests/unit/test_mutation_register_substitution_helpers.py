from r2morph.mutations.register_substitution import RegisterSubstitutionPass


def test_register_substitution_helpers():
    pass_obj = RegisterSubstitutionPass()

    assert pass_obj._get_register_class("x86")
    assert pass_obj._get_register_class("arm")
    assert pass_obj._get_register_class("mips") == {}

    instructions = [
        {"disasm": "mov eax, ebx"},
        {"disasm": "add ecx, 1"},
        {"disasm": "xor edx, edx"},
    ]
    candidates = pass_obj._find_substitution_candidates(instructions, "x86")
    assert isinstance(candidates, list)

    uses = pass_obj._count_register_uses(instructions, "eax")
    assert uses == 1

    # movzx safety: substituting source reg into same family as dest is unsafe
    # (e.g. movzx eax, al -> movzx eax, cl: cl in "c" family, but the
    #  original source "al" shares family "a" with dest "eax")
    # Replacing dest with a same-family register is the actual unsafe case
    assert pass_obj._is_safe_size_extension_substitution("movzx ebx, bl", "ebx", "ebx") is False

    # dest in different family from source is safe
    assert pass_obj._is_safe_size_extension_substitution("movzx eax, al", "eax", "edx") is True

    # dest family differs from source family and sizes are compatible
    assert pass_obj._is_safe_size_extension_substitution("movzx edx, al", "edx", "ecx") is True

    # LEA substitution safety
    assert pass_obj._is_safe_lea_substitution("lea rax, [rbx + rcx*4]", "rax", "r10") is True
    assert pass_obj._is_safe_lea_substitution("lea rax, [rbx + rcx*4]", "rbx", "r10") is False
