"""Conservative memory side-effect classification for data-flow analyses."""

from __future__ import annotations

_MIN_INSTRUCTION_PART_COUNT = 2

MEMORY_RESOURCE_NAME = "memory"
MEMORY_RESOURCE_SIZE = 0

_READ_MODIFY_WRITE_MNEMONICS = frozenset(
    {
        "adc",
        "add",
        "and",
        "bts",
        "btr",
        "btc",
        "cmpxchg",
        "dec",
        "inc",
        "neg",
        "not",
        "or",
        "rcl",
        "rcr",
        "rol",
        "ror",
        "sbb",
        "sar",
        "shl",
        "shr",
        "sub",
        "xadd",
        "xchg",
        "xor",
    }
)

_STACK_POINTERS = {
    "cdecl_32": ("esp", 32),
    "x86_32_linux": ("esp", 32),
    "x86_32_windows": ("esp", 32),
}
_STACK_POINTER_OPERATIONS = frozenset({"call", "pop", "popf", "popfq", "push", "pushf", "pushfq", "ret"})


def stack_pointer_effects(disasm: str, abi: str = "sysv_amd64") -> tuple[tuple[str, int], bool, bool]:
    """Return the implicit stack-pointer register and its read/write effects."""
    register = _STACK_POINTERS.get(abi, ("rsp", 64))
    tokens = disasm.split(None, 1)
    opcode = tokens[0].lower() if tokens else ""
    if opcode == "lock" and len(tokens) == _MIN_INSTRUCTION_PART_COUNT:
        opcode = tokens[1].split(None, 1)[0].lower()
    reads = opcode in _STACK_POINTER_OPERATIONS
    writes = opcode in {"pop", "popf", "popfq", "push", "pushf", "pushfq", "ret"}
    return register, reads, writes


def stack_pointer_registers(
    disasm: str, abi: str = "sysv_amd64", *, read: bool = False, write: bool = False
) -> tuple[tuple[str, int], ...]:
    """Return the stack-pointer register when the requested implicit effect exists."""
    register, reads, writes = stack_pointer_effects(disasm, abi)
    if (read and reads) or (write and writes):
        return (register,)
    return ()


def memory_accesses(disasm: str) -> tuple[bool, bool]:
    """Return conservative ``(reads, writes)`` effects for memory."""
    tokens = disasm.split(None, 1)
    if not tokens:
        return False, False
    opcode = tokens[0].lower()
    if opcode == "lock" and len(tokens) == _MIN_INSTRUCTION_PART_COUNT:
        opcode = tokens[1].split(None, 1)[0].lower()
    if opcode in {"call", "syscall", "sysenter", "int"}:
        return True, True
    if opcode in {"push", "pushf", "pushfq"}:
        return False, True
    if opcode in {"pop", "popf", "popfq", "ret"}:
        return True, False
    if opcode == "lea" or "[" not in disasm:
        return False, False

    operands = [operand.strip() for operand in tokens[1].split(",")]
    first_is_memory = bool(operands and "[" in operands[0])
    reads = any("[" in operand for operand in operands[1:])
    writes = first_is_memory
    if first_is_memory and opcode in _READ_MODIFY_WRITE_MNEMONICS:
        reads = True
    if opcode in {"cmp", "test", "bt"} and first_is_memory:
        reads = True
        writes = False
    return reads, writes
