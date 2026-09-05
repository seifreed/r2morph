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
