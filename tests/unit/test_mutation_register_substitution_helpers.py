from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.utils.assertions import expect


def test_register_substitution_helpers():
    pass_obj = RegisterSubstitutionPass()

    expect(pass_obj._get_register_class("x86"))
    expect(pass_obj._get_register_class("arm"))
    expect(pass_obj._get_register_class("mips") == {})

    instructions = [
        {"disasm": "mov eax, ebx"},
        {"disasm": "add ecx, 1"},
        {"disasm": "xor edx, edx"},
    ]
    candidates = pass_obj._find_substitution_candidates(instructions, "x86")
    expect(isinstance(candidates, list))

    uses = pass_obj._count_register_uses(instructions, "eax")
    expect(uses == 1)

    # movzx safety: substituting source reg into same family as dest is unsafe
    # (e.g. movzx eax, al -> movzx eax, cl: cl in "c" family, but the
    #  original source "al" shares family "a" with dest "eax")
    # Replacing dest with a same-family register is the actual unsafe case
    expect(not (pass_obj._is_safe_size_extension_substitution("movzx ebx, bl", "ebx", "ebx") is not False))

    # dest in different family from source is safe
    expect(not (pass_obj._is_safe_size_extension_substitution("movzx eax, al", "eax", "edx") is not True))

    # dest family differs from source family and sizes are compatible
    expect(not (pass_obj._is_safe_size_extension_substitution("movzx edx, al", "edx", "ecx") is not True))

    # Characterize the family/size contract guarded by _X86_REGISTER_FAMILIES
    # (actual behavior, captured against the implementation):
    # substituting the destination with a same-family register is unsafe.
    expect(not (pass_obj._is_safe_size_extension_substitution("movzx eax, al", "eax", "rax") is not False))
    # a size mismatch between original and substitute is unsafe.
    expect(not (pass_obj._is_safe_size_extension_substitution("movzx eax, al", "eax", "bx") is not False))
    # when destination size is not greater than source size, unsafe.
    expect(not (pass_obj._is_safe_size_extension_substitution("mov eax, ebx", "eax", "ecx") is not False))
    # cross-family substitutions of compatible sizes are safe.
    expect(not (pass_obj._is_safe_size_extension_substitution("movzx eax, bl", "bl", "cl") is not True))

    # LEA substitution safety
    expect(not (pass_obj._is_safe_lea_substitution("lea rax, [rbx + rcx*4]", "rax", "r10") is not True))
    expect(not (pass_obj._is_safe_lea_substitution("lea rax, [rbx + rcx*4]", "rbx", "r10") is not False))
