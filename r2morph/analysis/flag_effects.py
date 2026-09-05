"""Conservative status-flag effects shared by data-flow analyses."""

from __future__ import annotations

FLAGS_RESOURCE_NAME = "rflags"
FLAGS_RESOURCE_SIZE = 64

_FLAG_READING_MNEMONICS = frozenset(
    {
        "adc",
        "sbb",
        "rcl",
        "rcr",
        "lahf",
        "pushf",
        "pushfd",
        "pushfq",
    }
)
_FLAG_WRITING_MNEMONICS = frozenset(
    {
        "adc",
        "add",
        "and",
        "bt",
        "btc",
        "btr",
        "bts",
        "cmp",
        "cmpxchg",
        "clc",
        "cmc",
        "dec",
        "fcomi",
        "fcomip",
        "fucomi",
        "fucomip",
        "idiv",
        "imul",
        "inc",
        "int",
        "iret",
        "iretd",
        "iretq",
        "mul",
        "neg",
        "or",
        "popf",
        "popfd",
        "popfq",
        "rcl",
        "rcr",
        "rol",
        "ror",
        "sahf",
        "sar",
        "sbb",
        "shl",
        "shr",
        "stc",
        "sub",
        "syscall",
        "sysenter",
        "test",
        "ucomisd",
        "ucomiss",
        "vcomisd",
        "vcomiss",
        "vfucomisd",
        "vfucomiss",
        "xadd",
        "xor",
    }
)

_PREFIXES = frozenset({"bnd", "lock", "notrack", "rep", "repe", "repne", "repnz", "repz"})
_FLAG_BRANCH_EXCLUSIONS = frozenset({"jmp", "jcxz", "jecxz", "jrcxz"})


def _mnemonic(disasm: str) -> str:
    tokens = disasm.strip().lower().split()
    while tokens and tokens[0] in _PREFIXES:
        tokens.pop(0)
    return tokens[0] if tokens else ""


def flag_accesses(disasm: str) -> tuple[bool, bool]:
    """Return ``(reads, writes)`` for the architectural status flags."""
    mnemonic = _mnemonic(disasm)
    reads = mnemonic in _FLAG_READING_MNEMONICS or (
        mnemonic.startswith(("j", "cmov", "set")) and mnemonic not in _FLAG_BRANCH_EXCLUSIONS
    )
    writes = mnemonic in _FLAG_WRITING_MNEMONICS or mnemonic == "call"
    return reads, writes
