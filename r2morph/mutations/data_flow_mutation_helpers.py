"""Leaf helpers for data-flow mutation analysis and candidate selection."""

from __future__ import annotations

import random
from typing import Any

SAFE_INSTRUCTIONS = {
    "nop",
    "mov",
    "xor",
    "and",
    "or",
    "add",
    "sub",
    "shl",
    "shr",
    "not",
    "neg",
    "inc",
    "dec",
    "push",
    "pop",
    "lea",
    "test",
    "cmp",
}


def analyze_function_liveness(instructions: list[dict[str, Any]]) -> dict[int, set[str]]:
    """Perform a simple backward liveness analysis over instruction dicts."""
    live_in: dict[int, set[str]] = {}
    live_out: dict[int, set[str]] = {}

    x86_regs = {
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
    }

    for insn in reversed(instructions):
        addr = insn.get("addr", 0)
        disasm = insn.get("disasm", "").lower()

        used = set()
        defined = set()

        if "call" in disasm:
            used.update(["rdi", "rsi", "rdx", "rcx", "r8", "r9"])
            defined.update(["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"])

        parts = disasm.replace(",", " ").replace("[", " [ ").replace("]", " ] ").split()

        for i, part in enumerate(parts):
            if part in x86_regs:
                if i > 0 and parts[i - 1] in (
                    "mov",
                    "lea",
                    "xor",
                    "and",
                    "or",
                    "add",
                    "sub",
                    "shl",
                    "shr",
                    "not",
                    "neg",
                ):
                    defined.add(part)
                else:
                    used.add(part)

        next_addr = insn.get("next_addr", 0)
        succ_live = live_in.get(next_addr, set()) if next_addr else set()

        live_out[addr] = succ_live.copy()
        live_in[addr] = (used | (succ_live - defined)) & x86_regs

    return live_in


def get_dead_registers(addr: int, live_in: dict[int, set[str]], all_regs: set[str]) -> set[str]:
    """Return registers that are dead at a given address."""
    live = live_in.get(addr, set())
    return all_regs - live


def is_register_safe_to_use(
    reg: str,
    addr: int,
    live_in: dict[int, set[str]],
    caller_saved: set[str],
) -> bool:
    """Check if a register is caller-saved and dead at the given address."""
    if reg not in caller_saved:
        return False
    live = live_in.get(addr, set())
    return reg not in live


def find_safe_substitution_candidates(
    instructions: list[dict[str, Any]],
    live_in: dict[int, set[str]],
    arch: str,
) -> list[tuple[dict[str, Any], str, str]]:
    """Find instructions where register substitution is safe."""
    candidates = []

    caller_saved_64 = {
        "rax",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
    }
    caller_saved_32 = {"eax", "ecx", "edx"}

    caller_saved = caller_saved_64 if arch == "x86_64" else caller_saved_32
    all_regs = caller_saved.copy()

    for insn in instructions:
        addr = insn.get("addr", 0)
        disasm = insn.get("disasm", "").lower()

        mnemonic = disasm.split()[0] if disasm else ""
        if mnemonic not in SAFE_INSTRUCTIONS:
            continue

        dead_regs = get_dead_registers(addr, live_in, all_regs)
        if not dead_regs:
            continue

        for reg in sorted(caller_saved):
            if reg in disasm and reg in live_in.get(addr, set()):
                for dead_reg in sorted(dead_regs):
                    candidates.append((insn, reg, dead_reg))
                    break

    return candidates


def generate_dead_code_with_liveness(dead_regs: set[str], bits: int, size: int) -> list[str] | None:
    """Generate dead code that uses dead registers."""
    if not dead_regs:
        return None

    reg = random.choice(list(dead_regs))

    if bits == 64:
        patterns = [
            [f"push {reg}", f"mov {reg}, 0", f"xor {reg}, {reg}", f"pop {reg}"],
            [f"push {reg}", f"add {reg}, 1", f"sub {reg}, 1", f"pop {reg}"],
            [f"xor {reg}, {reg}", f"not {reg}", f"not {reg}"],
        ]
    else:
        patterns = [
            [f"push {reg}", f"mov {reg}, 0", f"pop {reg}"],
            [f"xor {reg}, {reg}"],
        ]

    return random.choice(patterns)


__all__ = [
    "SAFE_INSTRUCTIONS",
    "analyze_function_liveness",
    "find_safe_substitution_candidates",
    "generate_dead_code_with_liveness",
    "get_dead_registers",
    "is_register_safe_to_use",
]
