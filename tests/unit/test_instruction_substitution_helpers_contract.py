from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.instruction_substitution_helpers import (
    equivalent_flags_written,
    flags_live_after,
    get_equivalents,
    init_substitution_rules,
    instruction_flags_written,
    normalize_instruction,
    select_candidates,
)
from tests.utils.assertions import expect

_EXPECTED_ADDR_4096 = 0x1000
_EXPECTED_ADDR_8192 = 0x2000
_EXPECTED_TOTAL_FUNCTIONS = 2


class _Binary:
    def get_function_disasm(self, addr: int):
        if addr == _EXPECTED_ADDR_4096:
            return [{"disasm": "xor eax, eax"}]
        if addr == _EXPECTED_ADDR_8192:
            return [{"disasm": "mov rax, rbx"}]
        raise ValueError(addr)


class _FlagBinary:
    """Function whose zeroing instruction is followed by a flag read (`je`)."""

    def get_function_disasm(self, addr: int):
        return [
            {"disasm": "cmp ebx, ecx"},
            {"disasm": "xor eax, eax"},
            {"disasm": "je 0x1100"},
        ]


class _FunctionBudgetBinary:
    def __init__(self) -> None:
        self.requested_addresses: list[int] = []

    def is_analyzed(self) -> bool:
        return True

    def get_arch_family(self) -> tuple[str, int]:
        return ("x86", 64)

    def get_functions(self) -> list[dict[str, object]]:
        return [
            {"name": "first", "offset": 0x1000, "size": 64},
            {"name": "second", "offset": 0x2000, "size": 64},
        ]

    def get_function_disasm(self, addr: int) -> list[dict[str, object]]:
        self.requested_addresses.append(addr)
        return []


def test_instruction_substitution_helpers_cover_the_core_paths() -> None:
    equivalence_groups = {"x86": [["xor eax, eax", "sub eax, eax"]]}
    pattern_to_group = {"x86": {"xor eax, eax": 0}}

    expect(normalize_instruction("  XOR   EAX, EAX ") == "xor eax, eax")
    original, equivalents, group_idx = get_equivalents(
        {"disasm": "xor eax, eax"}, "x86", pattern_to_group, equivalence_groups
    )
    expect(original == "xor eax, eax")
    expect(equivalents == ["xor eax, eax", "sub eax, eax"])
    expect(group_idx == 0)

    binary = _Binary()
    functions = [
        {"name": "main", "offset": 0x1000, "size": 64},
        {"name": "tiny", "offset": 0x2000, "size": 4},
    ]
    selected = select_candidates(binary, functions, "x86", pattern_to_group, equivalence_groups)
    expect(selected[0][0]["name"] == "main")

    loaded_groups, loaded_patterns = init_substitution_rules()
    expect(not ("x86" not in loaded_groups))
    expect(not ("x86" not in loaded_patterns))


def test_flags_live_after_detects_conditional_jump() -> None:
    """A status flag read by a later conditional jump (before any flag write) is live."""
    expect(not (flags_live_after(["xor eax, eax", "je 0x10", "mov ebx, 1"], 0) is not True))


def test_flags_live_after_dead_before_syscall_and_after_overwrite() -> None:
    expect(not (flags_live_after(["mov rax, 0x3c", "xor edi, edi", "syscall"], 1) is not False))
    expect(not (flags_live_after(["xor eax, eax", "add ecx, edx", "je 0x10"], 0) is not False))


def test_flag_writes_classify_setting_vs_neutral_equivalents() -> None:
    expect(instruction_flags_written("xor eax, eax") == instruction_flags_written("sub eax, eax"))
    expect(equivalent_flags_written("mov eax, 0") == frozenset())
    expect(equivalent_flags_written("push 0; pop eax") == frozenset())
    expect(instruction_flags_written("xor eax, eax") != equivalent_flags_written("mov eax, 0"))


def test_select_candidates_marks_live_flags_for_zeroing_before_branch() -> None:
    """`xor eax, eax` between a `cmp` and a `je` has its flags live, so the pass can
    later reject flag-divergent equivalents (e.g. `mov eax, 0`)."""
    equivalence_groups = {"x86": [["xor eax, eax", "mov eax, 0", "sub eax, eax"]]}
    pattern_to_group = {"x86": {"xor eax, eax": 0}}
    functions = [{"name": "main", "offset": 0x1000, "size": 64}]
    selected = select_candidates(_FlagBinary(), functions, "x86", pattern_to_group, equivalence_groups)
    candidate = selected[0][1][0]
    expect(candidate["disasm"] == "xor eax, eax")
    expect(not (candidate["flags_live_after"] is not True))


def test_x86_64_substitution_does_not_use_32_bit_stack_self_move() -> None:
    equivalence_groups, pattern_to_group = init_substitution_rules()
    _, equivalents, _ = get_equivalents(
        {"disasm": "mov eax, eax"},
        "x86",
        pattern_to_group,
        equivalence_groups,
    )

    expect("push eax; pop eax" not in equivalents)


def test_x86_equivalence_rules_exclude_stack_side_effects() -> None:
    equivalence_groups, _ = init_substitution_rules()
    stack_effects = [
        instruction
        for group in equivalence_groups["x86"]
        for instruction in group
        if instruction.startswith(("push ", "pop "))
    ]

    expect(not stack_effects)


def test_instruction_substitution_applies_function_budget_before_disassembly() -> None:
    binary = _FunctionBudgetBinary()

    result = InstructionSubstitutionPass({"max_functions": 1}).apply(binary)

    expect(result["total_functions"] == _EXPECTED_TOTAL_FUNCTIONS)
    expect(result["functions_processed"] == 1)
    expect(binary.requested_addresses == [0x1000])
