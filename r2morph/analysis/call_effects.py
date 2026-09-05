"""Implicit register effects of call instructions."""

from __future__ import annotations

from typing import Any

_CALL_USED_REGISTERS: dict[str, tuple[tuple[str, int], ...]] = {
    "sysv_amd64": (
        ("rax", 64),
        ("rdi", 64),
        ("rsi", 64),
        ("rdx", 64),
        ("rcx", 64),
        ("r8", 64),
        ("r9", 64),
        *((f"xmm{index}", 128) for index in range(8)),
        *((f"ymm{index}", 256) for index in range(8)),
    ),
    "win64": (
        ("rcx", 64),
        ("rdx", 64),
        ("r8", 64),
        ("r9", 64),
        *((f"xmm{index}", 128) for index in range(4)),
        *((f"ymm{index}", 256) for index in range(4)),
    ),
    "cdecl_32": (),
}
_CALL_DEFINED_REGISTERS: dict[str, tuple[tuple[str, int], ...]] = {
    "sysv_amd64": (
        ("rax", 64),
        ("rdx", 64),
        ("rcx", 64),
        ("rsi", 64),
        ("rdi", 64),
        ("r8", 64),
        ("r9", 64),
        ("r10", 64),
        ("r11", 64),
        *((f"xmm{index}", 128) for index in range(16)),
        *((f"ymm{index}", 256) for index in range(16)),
    ),
    "win64": (
        ("rax", 64),
        ("rcx", 64),
        ("rdx", 64),
        ("r8", 64),
        ("r9", 64),
        ("r10", 64),
        ("r11", 64),
        *((f"xmm{index}", 128) for index in range(6)),
        *((f"ymm{index}", 256) for index in range(6)),
    ),
    "cdecl_32": (("eax", 32), ("ecx", 32), ("edx", 32)),
}
_ABI_ALIASES = {
    "x86_64_sysv": "sysv_amd64",
    "x86_64_windows": "win64",
    "x86_32_linux": "cdecl_32",
    "x86_32_windows": "cdecl_32",
}


def call_register_effects(
    abi: str = "sysv_amd64",
) -> tuple[tuple[tuple[str, int], ...], tuple[tuple[str, int], ...]]:
    """Return implicit call reads and writes for an ABI."""
    canonical_abi = _ABI_ALIASES.get(abi, abi)
    fallback = "sysv_amd64"
    return (
        _CALL_USED_REGISTERS.get(canonical_abi, _CALL_USED_REGISTERS[fallback]),
        _CALL_DEFINED_REGISTERS.get(canonical_abi, _CALL_DEFINED_REGISTERS[fallback]),
    )


def is_call_instruction(instruction: dict[str, Any]) -> bool:
    """Recognize direct and indirect call forms from type or disassembly."""
    instruction_type = str(instruction.get("type", "")).lower()
    disasm_mnemonic = str(instruction.get("disasm", "")).lower().split(None, 1)[0]
    return instruction_type.endswith("call") or disasm_mnemonic in {"call", "lcall"}
