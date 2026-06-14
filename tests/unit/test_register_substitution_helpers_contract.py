from r2morph.mutations.register_substitution_helpers import (
    get_register_class,
    is_safe_lea_substitution,
    is_safe_size_extension_substitution,
    select_candidates,
)


class _Binary:
    def get_function_disasm(self, addr: int):
        if addr == 0x1000:
            return [
                {"disasm": "mov eax, ebx"},
                {"disasm": "mov ecx, eax"},
            ]
        if addr == 0x2000:
            return [{"disasm": "mov rax, rbx"}]
        raise ValueError(addr)


def test_register_substitution_helpers_cover_the_core_paths() -> None:
    binary = _Binary()
    functions = [
        {"name": "main", "offset": 0x1000, "size": 64},
        {"name": "tiny", "offset": 0x2000, "size": 4},
    ]

    assert get_register_class("x64")["caller_saved"]
    assert is_safe_size_extension_substitution("movzx eax, bl", "bl", "cl") is True
    assert is_safe_lea_substitution("lea rax, [rbx + rcx*4]", "rax", "r8") is True
    assert select_candidates(binary, functions, "x86", 1.0, 2)[0][0]["name"] == "main"
