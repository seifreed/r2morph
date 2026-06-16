from r2morph.mutations.register_substitution_helpers import (
    find_substitution_candidates,
    get_register_class,
    is_safe_lea_substitution,
    is_safe_size_extension_substitution,
    select_candidates,
    syscall_live_registers,
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


def test_find_substitution_candidates_with_syscall_excludes_abi_number_register() -> None:
    """A register holding the syscall number is live into the operandless `syscall`
    instruction; renaming it (eax->edx) breaks the call. It must not be a candidate."""
    with_syscall = [
        {"disasm": "xor ecx, ecx"},
        {"disasm": "mov eax, 0x3c"},
        {"disasm": "syscall"},
    ]
    sources = {orig for orig, _ in find_substitution_candidates(with_syscall, "x86")}
    assert "eax" not in sources


def test_find_substitution_candidates_without_syscall_still_renames_eax() -> None:
    """The syscall guard must be targeted: with no system call, eax is a normal
    caller-saved register and stays substitutable."""
    no_syscall = [{"disasm": "mov eax, 0x3c"}, {"disasm": "ret"}]
    sources = {orig for orig, _ in find_substitution_candidates(no_syscall, "x86")}
    assert "eax" in sources


def test_syscall_live_registers_empty_when_no_syscall_present() -> None:
    assert syscall_live_registers([{"disasm": "mov eax, ebx"}, {"disasm": "int3"}]) == set()
