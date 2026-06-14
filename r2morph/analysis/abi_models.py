"""
ABI model definitions and specifications.

This module owns the ABI enums, dataclasses, and static specification table.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ABIType(Enum):
    """Supported ABI types."""

    X86_64_SYSTEM_V = "x86_64_sysv"
    X86_64_WINDOWS = "x86_64_windows"
    X86_32_LINUX = "x86_32_linux"
    X86_32_WINDOWS = "x86_32_windows"
    ARM64_AAPCS = "arm64_aapcs"
    ARM32_AAPCS = "arm32_aapcs"
    UNKNOWN = "unknown"


class ABIViolationType(Enum):
    """Types of ABI violations."""

    STACK_ALIGNMENT = "stack_alignment"
    RED_ZONE_CLOBBER = "red_zone_clobber"
    SHADOW_SPACE_VIOLATION = "shadow_space_violation"
    CALLEE_SAVED_CLOBBER = "callee_saved_clobber"
    CALLING_CONVENTION = "calling_convention"


@dataclass
class ABIViolation:
    """Represents an ABI violation detected during mutation."""

    violation_type: ABIViolationType
    description: str
    location: int
    details: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"<ABIViolation {self.violation_type.value} @ 0x{self.location:x}: {self.description}>"


@dataclass
class ABISpec:
    """ABI specification for a platform/architecture combination."""

    abi_type: ABIType
    stack_alignment: int
    red_zone_size: int
    shadow_space_size: int
    callee_saved_regs: list[str]
    param_regs: list[str]
    return_regs: list[str]

    def __repr__(self) -> str:
        return f"<ABISpec {self.abi_type.value}: align={self.stack_alignment}, red_zone={self.red_zone_size}, shadow={self.shadow_space_size}>"


ABI_SPECS: dict[str, ABISpec] = {
    "x86_64_sysv": ABISpec(
        abi_type=ABIType.X86_64_SYSTEM_V,
        stack_alignment=16,
        red_zone_size=128,
        shadow_space_size=0,
        callee_saved_regs=["rbx", "r12", "r13", "r14", "r15", "rbp"],
        param_regs=["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        return_regs=["rax", "rdx"],
    ),
    "x86_64_windows": ABISpec(
        abi_type=ABIType.X86_64_WINDOWS,
        stack_alignment=16,
        red_zone_size=0,
        shadow_space_size=32,
        callee_saved_regs=["rbx", "rdi", "rsi", "r12", "r13", "r14", "r15", "rbp"],
        param_regs=["rcx", "rdx", "r8", "r9"],
        return_regs=["rax"],
    ),
    "x86_32_linux": ABISpec(
        abi_type=ABIType.X86_32_LINUX,
        stack_alignment=4,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=["ebx", "esi", "edi", "ebp"],
        param_regs=[],
        return_regs=["eax", "edx"],
    ),
    "x86_32_windows": ABISpec(
        abi_type=ABIType.X86_32_WINDOWS,
        stack_alignment=4,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=["ebx", "esi", "edi", "ebp"],
        param_regs=[],
        return_regs=["eax", "edx"],
    ),
    "arm64_aapcs": ABISpec(
        abi_type=ABIType.ARM64_AAPCS,
        stack_alignment=16,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30"],
        param_regs=["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        return_regs=["x0", "x1"],
    ),
    "arm32_aapcs": ABISpec(
        abi_type=ABIType.ARM32_AAPCS,
        stack_alignment=8,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
        param_regs=["r0", "r1", "r2", "r3"],
        return_regs=["r0", "r1"],
    ),
}
