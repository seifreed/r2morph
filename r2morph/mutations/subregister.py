"""
Subregister-aware mutation utilities.

Provides functions for working with register sizes and subregisters
in x86-64, enabling size-aware code transformations.
"""

from typing import Optional, Final
from dataclasses import dataclass


@dataclass
class RegisterInfo:
    name: str
    size_bits: int
    base_register: str
    subregisters: tuple[Optional[str], ...]
    index: int


REG_64: Final[int] = 1
REG_32: Final[int] = 2
REG_16: Final[int] = 4
REG_8H: Final[int] = 8
REG_8L: Final[int] = 16
REG_ALL: Final[int] = REG_64 | REG_32 | REG_16 | REG_8H | REG_8L

REGISTER_MAP: dict[str, tuple[Optional[str], Optional[str], Optional[str], str]] = {
    "rax": (None, "eax", "ax", "al"),
    "rbx": (None, "ebx", "bx", "bl"),
    "rcx": (None, "ecx", "cx", "cl"),
    "rdx": (None, "edx", "dx", "dl"),
    "rsi": (None, "esi", "si", "sil"),
    "rdi": (None, "edi", "di", "dil"),
    "rbp": (None, "ebp", "bp", "bpl"),
    "rsp": (None, "esp", "sp", "spl"),
    "r8": (None, "r8d", "r8w", "r8b"),
    "r9": (None, "r9d", "r9w", "r9b"),
    "r10": (None, "r10d", "r10w", "r10b"),
    "r11": (None, "r11d", "r11w", "r11b"),
    "r12": (None, "r12d", "r12w", "r12b"),
    "r13": (None, "r13d", "r13w", "r13b"),
    "r14": (None, "r14d", "r14w", "r14b"),
    "r15": (None, "r15d", "r15w", "r15b"),
}

HIGH_BYTE_REGS: dict[str, tuple[str, str, str, str]] = {
    "rax": ("rax", "eax", "ax", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bh"),
    "rcx": ("rcx", "ecx", "cx", "ch"),
    "rdx": ("rdx", "edx", "dx", "dh"),
}

PRESERVED_REGS: Final[list[str]] = ["rbx", "rbp", "r12", "r13", "r14", "r15"]
SCRATCH_REGS: Final[list[str]] = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]


_register_info_cache: dict[str, RegisterInfo] = {}
_size_to_regs: dict[int, list[str]] = {64: [], 32: [], 16: [], 8: []}
_base_to_index: dict[str, int] = {}


def _init_caches():
    global _register_info_cache, _size_to_regs, _base_to_index

    if _register_info_cache:
        return

    for idx, (base, subregs) in enumerate(REGISTER_MAP.items()):
        _base_to_index[base] = idx

        size_64 = base
        size_32 = subregs[0]
        size_16 = subregs[1]
        size_8 = subregs[2] if len(subregs) > 2 else None

        _size_to_regs[64].append(size_64)
        if size_32:
            _size_to_regs[32].append(size_32)
        if size_16:
            _size_to_regs[16].append(size_16)
        if size_8:
            _size_to_regs[8].append(size_8)

        _register_info_cache[size_64] = RegisterInfo(
            name=size_64,
            size_bits=64,
            base_register=base,
            subregisters=subregs,
            index=idx,
        )

        if size_32:
            _register_info_cache[size_32] = RegisterInfo(
                name=size_32,
                size_bits=32,
                base_register=base,
                subregisters=subregs,
                index=idx,
            )

        if size_16:
            _register_info_cache[size_16] = RegisterInfo(
                name=size_16,
                size_bits=16,
                base_register=base,
                subregisters=subregs,
                index=idx,
            )

        if size_8:
            _register_info_cache[size_8] = RegisterInfo(
                name=size_8,
                size_bits=8,
                base_register=base,
                subregisters=subregs,
                index=idx,
            )

    for base, subregs in HIGH_BYTE_REGS.items():
        if len(subregs) > 3 and subregs[3]:
            _register_info_cache[subregs[3]] = RegisterInfo(
                name=subregs[3],
                size_bits=8,
                base_register=base,
                subregisters=subregs[:3],
                index=_base_to_index.get(base, 0),
            )


_init_caches()


def get_register_info(reg: str) -> Optional[RegisterInfo]:
    return _register_info_cache.get(reg.lower())


def get_base_register(reg: str) -> str:
    info = get_register_info(reg)
    return info.base_register if info else reg.lower()


def get_register_size(reg: str) -> int:
    info = get_register_info(reg)
    return info.size_bits if info else 0


def get_size_flag(reg: str) -> int:
    size = get_register_size(reg)
    if size == 64:
        return REG_64
    elif size == 32:
        return REG_32
    elif size == 16:
        return REG_16
    elif size == 8:
        return REG_8L | REG_8H
    return 0


def get_subregisters(reg: str) -> tuple[Optional[str], ...]:
    base = get_base_register(reg)
    return REGISTER_MAP.get(base, (None, None, None, None))


def get_subregister_by_size(reg: str, size_bits: int) -> Optional[str]:
    base = get_base_register(reg)
    subregs = REGISTER_MAP.get(base)

    if not subregs:
        return None

    if size_bits == 64:
        return base
    elif size_bits == 32:
        return subregs[0]
    elif size_bits == 16:
        return subregs[1]
    elif size_bits == 8:
        return subregs[2] if len(subregs) > 2 else None

    return None


def get_registers_by_size(size_bits: int) -> list[str]:
    return _size_to_refs.get(size_bits, []).copy()


def is_preserved_register(reg: str) -> bool:
    base = get_base_register(reg)
    return base in PRESERVED_REGS


def is_scratch_register(reg: str) -> bool:
    base = get_base_register(reg)
    return base in SCRATCH_REGS


def get_compatible_registers(reg: str, same_size: bool = True) -> list[str]:
    base = get_base_register(reg)
    size = get_register_size(reg)

    if same_size and size in _size_to_regs:
        return [r for r in _size_to_regs[size] if get_base_register(r) != base]

    result = []
    for size_bits, regs in _size_to_regs.items():
        for r in regs:
            if get_base_register(r) != base:
                result.append(r)

    return result


def get_random_compatible_register(reg: str, exclude: Optional[list[str]] = None) -> Optional[str]:
    import random

    compat = get_compatible_registers(reg, same_size=True)
    if exclude:
        compat = [r for r in compat if r not in exclude]

    if not compat:
        return None

    return random.choice(compat)


def registers_overlap(reg1: str, reg2: str) -> bool:
    base1 = get_base_register(reg1)
    base2 = get_base_register(reg2)
    return base1 == base2


def get_all_registers() -> list[str]:
    return list(REGISTER_MAP.keys())


def get_register_weights() -> dict[str, tuple[int, tuple[int, int, int, int]]]:
    return {
        "rax": (30, (10, 5, 2, 1)),
        "rbx": (20, (8, 4, 2, 1)),
        "rcx": (25, (10, 5, 2, 1)),
        "rdx": (25, (10, 5, 2, 1)),
        "rsi": (15, (6, 3, 1, 1)),
        "rdi": (15, (6, 3, 1, 1)),
        "rbp": (5, (2, 1, 1, 1)),
        "r8": (10, (4, 2, 1, 1)),
        "r9": (10, (4, 2, 1, 1)),
        "r10": (20, (8, 4, 2, 1)),
        "r11": (20, (8, 4, 2, 1)),
        "r12": (15, (6, 3, 1, 1)),
        "r13": (15, (6, 3, 1, 1)),
        "r14": (15, (6, 3, 1, 1)),
        "r15": (15, (6, 3, 1, 1)),
    }


_size_to_refs = _size_to_regs
