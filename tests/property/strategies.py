"""
Hypothesis strategies for property-based testing.

This module provides strategies for generating test cases
for mutation passes and semantic validation.
"""

from typing import Any
import random

try:
    from hypothesis import strategies as st
    from hypothesis.strategies import SearchStrategy

    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False
    st = None

from dataclasses import dataclass, field


@dataclass
class Instruction:
    """Simple instruction representation."""

    address: int
    mnemonic: str
    operands: list[str] = field(default_factory=list)
    size: int = 4
    bytes_data: bytes = b""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Function:
    """Simple function representation."""

    address: int
    name: str
    size: int
    instructions: list[Instruction] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


X86_REGISTERS_64 = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
]

X86_REGISTERS_32 = [
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "r8d",
    "r9d",
    "r10d",
    "r11d",
    "r12d",
    "r13d",
    "r14d",
    "r15d",
]

X86_INSTRUCTIONS_SIMPLE = [
    "nop",
    "ret",
    "syscall",
    "int3",
    "hlt",
    "leave",
    "cdq",
    "cqo",
]

X86_INSTRUCTIONS_ONE_REG = [
    "inc",
    "dec",
    "push",
    "pop",
    "not",
    "neg",
    "mul",
    "div",
]

X86_INSTRUCTIONS_TWO_REGS = [
    "mov",
    "add",
    "sub",
    "xor",
    "and",
    "or",
    "cmp",
    "test",
    "xchg",
    "lea",
]

X86_CONDITIONAL_JUMPS = [
    "je",
    "jne",
    "jz",
    "jnz",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "js",
    "jns",
    "jo",
    "jno",
]


def create_x86_register_strategy(bits: int = 64) -> "SearchStrategy[str]":
    """
    Create strategy for x86 register generation.

    Args:
        bits: Register size (32 or 64)

    Returns:
        Hypothesis strategy for register names
    """
    if not HYPOTHESIS_AVAILABLE:
        raise ImportError("Hypothesis not installed")

    if bits == 64:
        registers = X86_REGISTERS_64[:8]
    else:
        registers = X86_REGISTERS_32[:8]

    return st.sampled_from(registers)


def create_x86_instruction_strategy() -> "SearchStrategy[str]":
    """
    Create strategy for x86 instruction generation.

    Returns:
        Hypothesis strategy for instruction strings
    """
    if not HYPOTHESIS_AVAILABLE:
        raise ImportError("Hypothesis not installed")

    simple = st.sampled_from(X86_INSTRUCTIONS_SIMPLE)

    one_reg = st.builds(
        lambda mnemonic, reg: f"{mnemonic} {reg}",
        st.sampled_from(X86_INSTRUCTIONS_ONE_REG),
        create_x86_register_strategy(),
    )

    two_regs = st.builds(
        lambda mnemonic, reg1, reg2: f"{mnemonic} {reg1}, {reg2}",
        st.sampled_from(X86_INSTRUCTIONS_TWO_REGS),
        create_x86_register_strategy(),
        create_x86_register_strategy(),
    )

    return st.one_of(simple, one_reg, two_regs)


def create_instruction_sequence_strategy(
    min_size: int = 1,
    max_size: int = 20,
) -> "SearchStrategy[list[str]]":
    """
    Create strategy for instruction sequence generation.

    Args:
        min_size: Minimum sequence length
        max_size: Maximum sequence length

    Returns:
        Hypothesis strategy for instruction sequences
    """
    if not HYPOTHESIS_AVAILABLE:
        raise ImportError("Hypothesis not installed")

    return st.lists(
        create_x86_instruction_strategy(),
        min_size=min_size,
        max_size=max_size,
    )


def create_address_strategy(
    min_addr: int = 0x1000,
    max_addr: int = 0x10000,
) -> "SearchStrategy[int]":
    """
    Create strategy for address generation.

    Args:
        min_addr: Minimum address
        max_addr: Maximum address

    Returns:
        Hypothesis strategy for addresses
    """
    if not HYPOTHESIS_AVAILABLE:
        raise ImportError("Hypothesis not installed")

    return st.integers(min_value=min_addr, max_value=max_addr)


def create_function_strategy(
    min_instructions: int = 3,
    max_instructions: int = 20,
) -> "SearchStrategy[Function]":
    """
    Create strategy for function generation.

    Args:
        min_instructions: Minimum instruction count
        max_instructions: Maximum instruction count

    Returns:
        Hypothesis strategy for functions
    """
    if not HYPOTHESIS_AVAILABLE:
        raise ImportError("Hypothesis not installed")

    def make_function(instructions: list[str], address: int, name: str) -> Function:
        instr_objs = []
        current_addr = address
        for i, instr_str in enumerate(instructions):
            instr_objs.append(
                Instruction(
                    address=current_addr,
                    mnemonic=instr_str.split()[0],
                    operands=instr_str.split()[1:] if len(instr_str.split()) > 1 else [],
                    size=4,
                )
            )
            current_addr += 4

        return Function(
            address=address,
            name=name,
            size=current_addr - address,
            instructions=instr_objs,
        )

    return st.builds(
        make_function,
        create_instruction_sequence_strategy(min_instructions, max_instructions),
        create_address_strategy(),
        st.text(min_size=1, max_size=20).map(lambda s: f"func_{s}"),
    )


def create_mutation_seed_strategy() -> "SearchStrategy[int]":
    """
    Create strategy for mutation seed generation.

    Returns:
        Hypothesis strategy for random seeds
    """
    if not HYPOTHESIS_AVAILABLE:
        raise ImportError("Hypothesis not installed")

    return st.integers(min_value=0, max_value=2**32 - 1)


def create_mutation_pass_strategy() -> "SearchStrategy[str]":
    """
    Create strategy for mutation pass selection.

    Returns:
        Hypothesis strategy for mutation pass names
    """
    if not HYPOTHESIS_AVAILABLE:
        raise ImportError("Hypothesis not installed")

    passes = [
        "nop_insertion",
        "register_substitution",
        "instruction_expansion",
        "dead_code_insertion",
        "opaque_predicate",
        "fake_jump",
    ]

    return st.sampled_from(passes)


def create_function_with_loops_strategy() -> "SearchStrategy[Function]":
    """
    Create strategy for functions with loop patterns.

    Returns:
        Hypothesis strategy for functions with loops
    """
    if not HYPOTHESIS_AVAILABLE:
        raise ImportError("Hypothesis not installed")

    def make_loopy_function(
        pre_loop: list[str],
        loop_body: list[str],
        post_loop: list[str],
        address: int,
    ) -> Function:
        instructions = []

        current_addr = address
        for instr_str in pre_loop:
            instructions.append(
                Instruction(
                    address=current_addr,
                    mnemonic=instr_str.split()[0],
                    operands=instr_str.split()[1:] if len(instr_str.split()) > 1 else [],
                    size=4,
                )
            )
            current_addr += 4

        loop_start = current_addr
        for instr_str in loop_body:
            instructions.append(
                Instruction(
                    address=current_addr,
                    mnemonic=instr_str.split()[0],
                    operands=instr_str.split()[1:] if len(instr_str.split()) > 1 else [],
                    size=4,
                )
            )
            current_addr += 4

        instructions.append(
            Instruction(
                address=current_addr,
                mnemonic="jmp",
                operands=[f"0x{loop_start:x}"],
                size=4,
            )
        )
        current_addr += 4

        for instr_str in post_loop:
            instructions.append(
                Instruction(
                    address=current_addr,
                    mnemonic=instr_str.split()[0],
                    operands=instr_str.split()[1:] if len(instr_str.split()) > 1 else [],
                    size=4,
                )
            )
            current_addr += 4

        return Function(
            address=address,
            name=f"func_{address:x}",
            size=current_addr - address,
            instructions=instructions,
            metadata={"has_loop": True, "loop_start": loop_start},
        )

    return st.builds(
        make_loopy_function,
        create_instruction_sequence_strategy(1, 5),
        create_instruction_sequence_strategy(2, 10),
        create_instruction_sequence_strategy(1, 5),
        create_address_strategy(),
    )


def create_function_with_branches_strategy() -> "SearchStrategy[Function]":
    """
    Create strategy for functions with conditional branches.

    Returns:
        Hypothesis strategy for functions with branches
    """
    if not HYPOTHESIS_AVAILABLE:
        raise ImportError("Hypothesis not installed")

    def make_branched_function(
        preamble: list[str],
        then_branch: list[str],
        else_branch: list[str],
        address: int,
        cond_jump: str,
    ) -> Function:
        instructions = []
        current_addr = address

        for instr_str in preamble:
            instructions.append(
                Instruction(
                    address=current_addr,
                    mnemonic=instr_str.split()[0],
                    operands=instr_str.split()[1:] if len(instr_str.split()) > 1 else [],
                    size=4,
                )
            )
            current_addr += 4

        else_start = current_addr + 4 * (len(then_branch) + 1)
        merge_addr = else_start + 4 * len(else_branch)

        instructions.append(
            Instruction(
                address=current_addr,
                mnemonic=cond_jump,
                operands=[f"0x{else_start:x}"],
                size=4,
            )
        )
        current_addr += 4

        for instr_str in then_branch:
            instructions.append(
                Instruction(
                    address=current_addr,
                    mnemonic=instr_str.split()[0],
                    operands=instr_str.split()[1:] if len(instr_str.split()) > 1 else [],
                    size=4,
                )
            )
            current_addr += 4

        instructions.append(
            Instruction(
                address=current_addr,
                mnemonic="jmp",
                operands=[f"0x{merge_addr:x}"],
                size=4,
            )
        )
        current_addr += 4

        for instr_str in else_branch:
            instructions.append(
                Instruction(
                    address=current_addr,
                    mnemonic=instr_str.split()[0],
                    operands=instr_str.split()[1:] if len(instr_str.split()) > 1 else [],
                    size=4,
                )
            )
            current_addr += 4

        return Function(
            address=address,
            name=f"func_{address:x}",
            size=current_addr - address,
            instructions=instructions,
            metadata={"has_branches": True},
        )

    return st.builds(
        make_branched_function,
        create_instruction_sequence_strategy(1, 3),
        create_instruction_sequence_strategy(1, 5),
        create_instruction_sequence_strategy(1, 5),
        create_address_strategy(),
        st.sampled_from(X86_CONDITIONAL_JUMPS),
    )


def create_binary_with_functions_strategy(
    min_functions: int = 1,
    max_functions: int = 10,
) -> "SearchStrategy[list[Function]]":
    """
    Create strategy for generating multiple functions.

    Args:
        min_functions: Minimum number of functions
        max_functions: Maximum number of functions

    Returns:
        Hypothesis strategy for lists of functions
    """
    if not HYPOTHESIS_AVAILABLE:
        raise ImportError("Hypothesis not installed")

    return st.lists(
        create_function_strategy(),
        min_size=min_functions,
        max_size=max_functions,
    )


def get_simple_instruction() -> str:
    """Get a simple random instruction (for non-Hypothesis testing)."""
    registers = X86_REGISTERS_64[:8]
    instructions = []

    instructions.extend(X86_INSTRUCTIONS_SIMPLE)

    for mnemonic in X86_INSTRUCTIONS_ONE_REG:
        instructions.append(f"{mnemonic} {random.choice(registers)}")

    for mnemonic in X86_INSTRUCTIONS_TWO_REGS:
        reg1, reg2 = random.sample(registers, 2)
        instructions.append(f"{mnemonic} {reg1}, {reg2}")

    return random.choice(instructions)


def get_simple_function(address: int = 0x1000, num_instructions: int = 5) -> Function:
    """Get a simple random function (for non-Hypothesis testing)."""
    instructions = []
    current_addr = address

    for i in range(num_instructions):
        instr_str = get_simple_instruction()
        instructions.append(
            Instruction(
                address=current_addr,
                mnemonic=instr_str.split()[0],
                operands=instr_str.split()[1:] if len(instr_str.split()) > 1 else [],
                size=4,
            )
        )
        current_addr += 4

    return Function(
        address=address,
        name=f"func_{address:x}",
        size=current_addr - address,
        instructions=instructions,
    )


if HYPOTHESIS_AVAILABLE:
    __all__ = [
        "create_x86_register_strategy",
        "create_x86_instruction_strategy",
        "create_instruction_sequence_strategy",
        "create_address_strategy",
        "create_function_strategy",
        "create_function_with_loops_strategy",
        "create_function_with_branches_strategy",
        "create_binary_with_functions_strategy",
        "create_mutation_seed_strategy",
        "create_mutation_pass_strategy",
        "Instruction",
        "Function",
    ]
else:
    __all__ = [
        "get_simple_instruction",
        "get_simple_function",
        "Instruction",
        "Function",
    ]
