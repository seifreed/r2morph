"""Calling-convention tables for type inference."""

from __future__ import annotations

from typing import Any

_SYSV_AMD64_CONVENTION: dict[str, Any] = {
    "param_registers": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "return_register": "rax",
    "callee_saved": ["rbx", "rbp", "r12", "r13", "r14", "r15"],
    "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
}

_CDECL_X86_32_CONVENTION: dict[str, Any] = {
    "param_registers": [],
    "return_register": "eax",
    "callee_saved": ["ebx", "esi", "edi", "ebp"],
    "caller_saved": ["eax", "ecx", "edx"],
    "stack_params": True,
}

_AAPCS_ARM32_CONVENTION: dict[str, Any] = {
    "param_registers": ["r0", "r1", "r2", "r3"],
    "return_register": "r0",
    "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
    "caller_saved": ["r0", "r1", "r2", "r3", "r12", "lr"],
}

_AAPCS64_ARM64_CONVENTION: dict[str, Any] = {
    "param_registers": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "return_register": "x0",
    "callee_saved": [
        "x19",
        "x20",
        "x21",
        "x22",
        "x23",
        "x24",
        "x25",
        "x26",
        "x27",
        "x28",
    ],
    "caller_saved": [
        "x0",
        "x1",
        "x2",
        "x3",
        "x4",
        "x5",
        "x6",
        "x7",
        "x8",
        "x9",
        "x10",
        "x11",
        "x12",
        "x13",
        "x14",
        "x15",
        "x16",
        "x17",
        "x18",
    ],
}

_EMPTY_CONVENTION: dict[str, Any] = {
    "param_registers": [],
    "return_register": "",
    "callee_saved": [],
    "caller_saved": [],
}


__all__ = [
    "_SYSV_AMD64_CONVENTION",
    "_CDECL_X86_32_CONVENTION",
    "_AAPCS_ARM32_CONVENTION",
    "_AAPCS64_ARM64_CONVENTION",
    "_EMPTY_CONVENTION",
]
