"""
Register tracking for semantic preservation during mutations.

Tracks which registers are stored on the stack to ensure
junk code generation preserves program semantics.
"""

from dataclasses import dataclass
from typing import Optional
from collections import OrderedDict


@dataclass
class StackEntry:
    register: str
    restore_code: bytes
    size: int = 8


class RegTracker:
    """
    Tracks register state during code generation.

    Manages push/pop pairs for register preservation,
    enabling semantic-neutral junk code generation.
    """

    X86_64_GPR = {
        "rax": ("eax", "ax", "ah", "al"),
        "rbx": ("ebx", "bx", "bh", "bl"),
        "rcx": ("ecx", "cx", "ch", "cl"),
        "rdx": ("edx", "dx", "dh", "dl"),
        "rsi": ("esi", "si", None, "sil"),
        "rdi": ("edi", "di", None, "dil"),
        "rbp": ("ebp", "bp", None, "bpl"),
        "r8": ("r8d", "r8w", None, "r8b"),
        "r9": ("r9d", "r9w", None, "r9b"),
        "r10": ("r10d", "r10w", None, "r10b"),
        "r11": ("r11d", "r11w", None, "r11b"),
        "r12": ("r12d", "r12w", None, "r12b"),
        "r13": ("r13d", "r13w", None, "r13b"),
        "r14": ("r14d", "r14w", None, "r14b"),
        "r15": ("r15d", "r15w", None, "r15b"),
    }

    X86_64_REG_SIZES = {
        64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"],
        32: [
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "r8d",
            "r9d",
            "r10d",
            "r11d",
            "r12d",
            "r13d",
            "r14d",
            "r15d",
        ],
        16: ["ax", "bx", "cx", "dx", "si", "di", "bp", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"],
        8: ["al", "bl", "cl", "dl", "sil", "dil", "bpl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"],
    }

    REG_SIZE_FLAGS = {
        "REG_64": 1,
        "REG_32": 2,
        "REG_16": 4,
        "REG_8H": 8,
        "REG_8L": 16,
        "REG_ALL": 1 | 2 | 4 | 8 | 16,
    }

    REG_WEIGHTS = {
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

    PRESERVED_REGS = ["rbx", "rbp", "r12", "r13", "r14", "r15"]
    SCRATCH_REGS = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]

    def __init__(self) -> None:
        self._stack: OrderedDict[str, StackEntry] = OrderedDict()
        self._stack_depth: int = 0

    def store_register(self, reg: str, restore_code: bytes) -> None:
        if reg in self._stack:
            return
        self._stack[reg] = StackEntry(register=reg, restore_code=restore_code, size=8)
        self._stack_depth += 1

    def restore_register(self, reg: str) -> Optional[bytes]:
        if reg not in self._stack:
            return None
        entry = self._stack.pop(reg)
        self._stack_depth -= 1
        return entry.restore_code

    def is_stored(self, reg: str) -> bool:
        return reg in self._stack

    def get_stored_registers(self) -> list[str]:
        return list(self._stack.keys())

    def get_top_stack_register(self) -> tuple[Optional[str], bytes]:
        if not self._stack:
            return None, b""
        reg = list(self._stack.keys())[-1]
        return reg, self._stack[reg].restore_code

    def get_stack_depth(self) -> int:
        return self._stack_depth

    def clear(self) -> None:
        self._stack.clear()
        self._stack_depth = 0

    def get_subregisters(self, reg: str) -> Optional[tuple]:
        return self.X86_64_GPR.get(reg)

    def get_register_size(self, reg: str) -> int:
        for size, regs in self.X86_64_REG_SIZES.items():
            if reg in regs:
                return size
        return 0

    def is_preserved_reg(self, reg: str) -> bool:
        base_reg = self._get_base_register(reg)
        return base_reg in self.PRESERVED_REGS

    def is_scratch_reg(self, reg: str) -> bool:
        base_reg = self._get_base_register(reg)
        return base_reg in self.SCRATCH_REGS

    def _get_base_register(self, reg: str) -> str:
        reg_lower = reg.lower()
        for base, subregs in self.X86_64_GPR.items():
            if reg_lower == base or reg_lower in subregs:
                return base
        return reg_lower

    def get_compatible_registers(self, reg: str, exclude_stored: bool = False) -> list[str]:
        self._get_base_register(reg)
        size = self.get_register_size(reg)

        if size not in self.X86_64_REG_SIZES:
            return []

        compatible = []
        for r in self.X86_64_REG_SIZES[size]:
            if exclude_stored and self.is_stored(self._get_base_register(r)):
                continue
            if r != reg:
                compatible.append(r)

        return compatible

    def get_register_weights(self) -> tuple[list[str], list[int]]:
        regs = list(self.REG_WEIGHTS.keys())
        weights = [self.REG_WEIGHTS[r][0] for r in regs]
        return regs, weights

    def get_subregister_weights(self, reg: str) -> tuple[tuple[str | None, ...], tuple[int, ...]] | None:
        if reg not in self.X86_64_GPR:
            return None
        subregs: tuple[str | None, ...] = (reg,) + self.X86_64_GPR[reg]
        weights: tuple[int, ...] = (self.REG_WEIGHTS[reg][0],) + self.REG_WEIGHTS[reg][1]
        return subregs, weights


REGISTER_SIZE_FLAGS = {
    64: 1,
    32: 2,
    16: 4,
    8: 16,
}

REG_64 = 1
REG_32 = 2
REG_16 = 4
REG_8H = 8
REG_8L = 16
REG_ALL = REG_64 | REG_32 | REG_16 | REG_8H | REG_8L

REG_SIZES_MAP: dict[str, int] = {}
for _reg in RegTracker.X86_64_GPR:
    REG_SIZES_MAP[_reg] = REG_64
    REG_SIZES_MAP[RegTracker.X86_64_GPR[_reg][0]] = REG_32
    REG_SIZES_MAP[RegTracker.X86_64_GPR[_reg][1]] = REG_16
    _high_reg = RegTracker.X86_64_GPR[_reg][2]
    if _high_reg is not None:
        REG_SIZES_MAP[_high_reg] = REG_8H
    REG_SIZES_MAP[RegTracker.X86_64_GPR[_reg][3]] = REG_8L

REG_WEIGHTS_MAP: dict[str, tuple[int, tuple[int, int, int, int]]] = {
    reg: weights for reg, weights in RegTracker.REG_WEIGHTS.items()
}
