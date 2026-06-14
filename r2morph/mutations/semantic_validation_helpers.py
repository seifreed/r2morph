"""Pure helpers for semantic validation."""

from __future__ import annotations

from typing import Any

PRESERVED_REGISTERS_64 = ["rbx", "rbp", "r12", "r13", "r14", "r15"]
SCRATCH_REGISTERS_64 = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
ALL_REGISTERS_64 = PRESERVED_REGISTERS_64 + SCRATCH_REGISTERS_64

PUSH_OPCODES = {"push", "pushq", "pushl", "pushw"}
POP_OPCODES = {"pop", "popq", "popl", "popw"}
CONTROL_FLOW_OPCODES = {
    "jmp",
    "je",
    "jne",
    "jz",
    "jnz",
    "jg",
    "jl",
    "jge",
    "jle",
    "ja",
    "jb",
    "jae",
    "jbe",
    "call",
    "ret",
    "retn",
}
UNSAFE_OPCODES = {"syscall", "int", "int3", "ud2", "hlt", "cli", "sti"}


def get_mnemonic(ins: dict[str, Any]) -> str:
    return (ins.get("mnemonic") or ins.get("type") or "").lower()


def get_address(ins: dict[str, Any]) -> int:
    addr = ins.get("addr", ins.get("address", 0))
    return int(addr, 0) if isinstance(addr, str) else addr


def get_operand(ins: dict[str, Any], idx: int) -> str | None:
    ops = ins.get("operands", [])
    if isinstance(ops, dict):
        return ops.get(str(idx)) or ops.get(idx)
    if isinstance(ops, list) and idx < len(ops):
        result = ops[idx]
        return str(result) if result is not None else None
    op_key = f"operand_{idx + 1}"
    result = ins.get(op_key)
    return str(result) if result is not None else None


def get_jump_target(ins: dict[str, Any]) -> int | None:
    jump = ins.get("jump") or ins.get("target")
    if jump:
        try:
            return int(jump, 0) if isinstance(jump, str) else jump
        except (ValueError, TypeError):
            pass
    return None
