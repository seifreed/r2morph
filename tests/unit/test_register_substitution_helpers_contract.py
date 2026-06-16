from r2morph.mutations.register_substitution_helpers import (
    abi_live_registers,
    find_substitution_candidates,
    get_register_class,
    implicit_operand_pins,
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


def test_abi_live_registers_empty_when_no_transfer_present() -> None:
    assert abi_live_registers([{"disasm": "mov eax, ebx"}, {"disasm": "int3"}]) == set()


def test_find_substitution_candidates_with_arm64_call_excludes_argument_register() -> None:
    """x0 holds the first argument read implicitly by `bl`; renaming it (x0->x4)
    corrupts the call. It must not be a candidate when a call is present."""
    with_call = [
        {"disasm": "add x0, x0, str.hello"},
        {"disasm": "bl sym.imp.puts"},
        {"disasm": "mov w0, 0"},
        {"disasm": "ret"},
    ]
    sources = {orig for orig, _ in find_substitution_candidates(with_call, "arm64")}
    assert "x0" not in sources


def test_find_substitution_candidates_with_x64_call_excludes_argument_register() -> None:
    """rdi carries the first integer argument into a `call`; it must not be renamed."""
    with_call = [
        {"disasm": "mov rdi, rbx"},
        {"disasm": "call sym.imp.puts"},
        {"disasm": "ret"},
    ]
    sources = {orig for orig, _ in find_substitution_candidates(with_call, "x64")}
    assert "rdi" not in sources


def test_find_substitution_candidates_without_call_still_renames_arg_register() -> None:
    """The call guard must be targeted: with no call, x0 is a normal register."""
    no_call = [{"disasm": "add x0, x0, x1"}, {"disasm": "mov x2, x0"}, {"disasm": "ret"}]
    sources = {orig for orig, _ in find_substitution_candidates(no_call, "arm64")}
    assert "x0" in sources


def test_call_live_registers_empty_when_no_call_present() -> None:
    assert abi_live_registers([{"disasm": "mov x0, x1"}, {"disasm": "ret"}]) == set()


def test_abi_live_registers_allows_dead_register_before_syscall() -> None:
    """The dataflow analysis must free a register whose value is overwritten before
    the syscall: here the early `eax` computation is dead once `rax` is loaded with
    the syscall number, so only `rax` (not `eax`) is unsafe."""
    window = [
        {"disasm": "mov eax, 5"},
        {"disasm": "add eax, 2"},
        {"disasm": "mov rax, 0x3c"},
        {"disasm": "xor edi, edi"},
        {"disasm": "syscall"},
    ]
    unsafe = abi_live_registers(window)
    assert "rax" in unsafe
    assert "eax" not in unsafe


def test_abi_live_registers_excludes_token_reading_call_return() -> None:
    """A token that reads a call's return value (rax) before redefining it is unsafe;
    renaming it would read a different physical register than the call wrote."""
    window = [
        {"disasm": "call sym.imp.rand"},
        {"disasm": "mov rbx, rax"},
        {"disasm": "ret"},
    ]
    assert "rax" in abi_live_registers(window)


def test_find_substitution_candidates_excludes_mul_implicit_registers() -> None:
    """`mul` reads rax and writes rdx:rax implicitly; renaming either corrupts it."""
    window = [
        {"disasm": "mov rax, 5"},
        {"disasm": "mul rbx"},
        {"disasm": "mov rcx, rax"},
        {"disasm": "ret"},
    ]
    sources = {orig for orig, _ in find_substitution_candidates(window, "x64")}
    assert "rax" not in sources
    assert "rdx" not in sources


def test_find_substitution_candidates_excludes_rep_string_registers() -> None:
    """`rep movsb` uses rsi/rdi/rcx implicitly as pointers and counter."""
    window = [{"disasm": "mov rcx, 16"}, {"disasm": "rep movsb"}, {"disasm": "ret"}]
    sources = {orig for orig, _ in find_substitution_candidates(window, "x64")}
    assert "rcx" not in sources


def test_implicit_operand_pins_skips_two_operand_imul() -> None:
    """Two-operand `imul rax, rbx` is explicit, so it pins nothing (rax stays free)."""
    assert implicit_operand_pins([{"disasm": "imul rax, rbx"}]) == set()
    assert "rax" in implicit_operand_pins([{"disasm": "imul rbx"}])


def test_implicit_operand_pins_empty_without_implicit_instructions() -> None:
    assert implicit_operand_pins([{"disasm": "mov rax, rbx"}, {"disasm": "add rcx, 1"}]) == set()
