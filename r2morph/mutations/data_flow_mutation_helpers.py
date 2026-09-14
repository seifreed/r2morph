"""Leaf helpers for data-flow mutation analysis and candidate selection."""

from __future__ import annotations

import re
from typing import Any

import r2morph.core.randomness as random
from r2morph.analysis.dataflow_models import Register
from r2morph.core.constants import ARCH_BITS_64

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

_CALLER_SAVED_REGISTERS = {
    "x86_64": frozenset({"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}),
    "x86": frozenset({"eax", "ecx", "edx"}),
}
_TWO_OPERANDS = 2
_X86_32_BITS = 32
_X86_64_BITS = ARCH_BITS_64
_REGISTER_WIDTHS = {
    **{register: 64 for register in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")},
    **{register: 32 for register in ("eax", "ebx", "ecx", "edx", "esi", "edi")},
}
_REGISTER_OPERAND = re.compile(r"^[a-z][a-z0-9]*$")


def _register_aliases(register: str) -> set[str]:
    return {alias.name for alias in Register(register).aliases()}


def _definition_kills_use(definition: str, use: str) -> bool:
    definition_register = Register(definition)
    use_register = Register(use)
    if _register_aliases(definition).isdisjoint(_register_aliases(use)):
        return False
    return definition_register.size >= use_register.size or (
        definition_register.size == _X86_32_BITS and use_register.size == _X86_64_BITS
    )


def _register_is_live(register: str, live: set[str]) -> bool:
    return any(not _register_aliases(register).isdisjoint(_register_aliases(current)) for current in live)


def _remove_killed_registers(live: set[str], defined: set[str]) -> set[str]:
    return {
        register for register in live if not any(_definition_kills_use(definition, register) for definition in defined)
    }


def _successors(instruction: dict[str, Any], ordered_addresses: list[int]) -> tuple[int, ...]:
    """Return CFG successors, falling back to the supplied linear edge."""
    address = instruction.get("addr", 0)
    next_address = instruction.get("next_addr", 0)
    position = ordered_addresses.index(address) if address in ordered_addresses else -1
    linear_successor = (
        next_address
        if isinstance(next_address, int) and next_address
        else ordered_addresses[position + 1] if position >= 0 and position + 1 < len(ordered_addresses) else 0
    )
    instruction_type = instruction.get("type", "")
    mnemonic = str(instruction.get("disasm", "")).lower().split(maxsplit=1)[0]
    jump = instruction.get("jump")
    fail = instruction.get("fail")
    if instruction_type == "jmp" or mnemonic == "jmp":
        return (jump,) if isinstance(jump, int) and jump else ()
    if instruction_type == "cjmp" or mnemonic.startswith("j"):
        return tuple(
            target
            for target in (jump, fail, linear_successor)
            if isinstance(target, int) and target and target not in (address,)
        )
    if mnemonic.startswith(("ret", "ud", "hlt", "int")):
        return ()
    return (linear_successor,) if linear_successor else ()


def _split_register_instruction(disasm: str) -> tuple[str, str, str] | None:
    """Return mnemonic and operands for a simple two-operand register write."""
    parts = disasm.lower().split(maxsplit=1)
    if len(parts) != _TWO_OPERANDS or parts[0] not in {"mov", "lea"}:
        return None
    operands = tuple(part.strip() for part in parts[1].split(","))
    if len(operands) != _TWO_OPERANDS or not _REGISTER_OPERAND.fullmatch(operands[0]):
        return None
    if parts[0] == "mov" and "[" in operands[1]:
        return None
    return parts[0], operands[0], operands[1]


def substitute_destination_register(disasm: str, original: str, substitute: str) -> str | None:
    """Replace only an instruction's destination register.

    Replacing every textual occurrence also rewrites address operands such as
    ``lea rdi, [rdi + 8]`` and changes the instruction's meaning.
    """
    parts = disasm.split(maxsplit=1)
    if len(parts) != _TWO_OPERANDS:
        return None
    operands = parts[1].split(",", 1)
    if len(operands) != _TWO_OPERANDS or operands[0].strip().lower() != original.lower():
        return None
    return f"{parts[0]} {substitute},{operands[1]}"


def _same_register_width(first: str, second: str) -> bool:
    return _REGISTER_WIDTHS.get(first) == _REGISTER_WIDTHS.get(second)


def _implicit_register_effects(disasm: str) -> tuple[set[str], set[str]]:
    used: set[str] = set()
    defined: set[str] = set()
    if "call" in disasm:
        used.update(["rdi", "rsi", "rdx", "rcx", "r8", "r9"])
        defined.update(["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"])
    if disasm.startswith("syscall"):
        used.update(["rax", "eax", "rdi", "rsi", "rdx", "r10", "r8", "r9"])
        defined.update(["rax", "eax"])
    if disasm.startswith("ret"):
        used.update(["rax", "eax"])
    if "cmpxchg" in disasm:
        used.add("rax")
    memory = re.search(r"\[([^]]+)\]", disasm)
    if memory:
        for register in _REGISTER_WIDTHS:
            if re.search(rf"(?<![a-z0-9]){re.escape(register)}(?![a-z0-9])", memory.group(1)):
                used.add(register)
    return used, defined


def analyze_function_liveness(instructions: list[dict[str, Any]]) -> dict[int, set[str]]:
    """Perform a CFG-aware backward liveness analysis over instruction dicts."""
    live_in: dict[int, set[str]] = {}
    live_out: dict[int, set[str]] = {}

    x86_regs = {
        alias.name
        for register in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")
        for alias in Register(register).aliases()
    }
    read_modify_write = {"add", "and", "dec", "inc", "neg", "not", "or", "sub", "xor"}
    write_only = {"lea", "mov", "pop"}

    ordered_addresses = [insn.get("addr", 0) for insn in instructions if isinstance(insn.get("addr"), int)]
    use_def: dict[int, tuple[set[str], set[str]]] = {}
    successors: dict[int, tuple[int, ...]] = {}
    for insn in instructions:
        addr = insn.get("addr", 0)
        disasm = insn.get("disasm", "").lower()

        used, defined = _implicit_register_effects(disasm)

        parts = disasm.replace(",", " ").replace("[", " [ ").replace("]", " ] ").split()

        for i, part in enumerate(parts):
            if part in x86_regs:
                if i > 0 and parts[i - 1] in read_modify_write:
                    used.add(part)
                    defined.add(part)
                elif i > 0 and parts[i - 1] in write_only:
                    defined.add(part)
                else:
                    used.add(part)

        if isinstance(addr, int):
            use_def[addr] = (used, defined)
            successors[addr] = _successors(insn, ordered_addresses)

    changed = True
    while changed:
        changed = False
        for addr in reversed(ordered_addresses):
            used, defined = use_def[addr]
            successor_live = {register for successor in successors[addr] for register in live_in.get(successor, set())}
            next_live_out = successor_live & x86_regs
            next_live_in = (used | _remove_killed_registers(next_live_out, defined)) & x86_regs
            if live_out.get(addr) != next_live_out or live_in.get(addr) != next_live_in:
                live_out[addr] = next_live_out
                live_in[addr] = next_live_in
                changed = True

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
    """Find register writes whose destination is dead after the instruction.

    Replacing a source operand with a dead register changes the value flowing
    through the instruction. Only ``mov`` and ``lea`` destinations are
    considered because they do not modify flags, and the destination must be
    dead on the next instruction's live-in set.
    """
    candidates = []

    caller_saved = _CALLER_SAVED_REGISTERS.get(arch, frozenset())

    for insn in instructions:
        addr = insn.get("addr", 0)
        disasm = insn.get("disasm", "").lower()
        parsed = _split_register_instruction(disasm)
        next_addr = insn.get("next_addr", 0)
        if parsed is None or not next_addr:
            continue
        _mnemonic, destination, source = parsed
        live_after = live_in.get(next_addr, set())
        live_before = live_in.get(addr, set())
        if destination not in caller_saved or _register_is_live(destination, live_after):
            continue

        dead_regs = sorted(
            register
            for register in caller_saved
            if not _register_is_live(register, live_before)
            and register not in {source, destination}
            and not _register_aliases(register) & _register_aliases(source)
        )
        for dead_reg in dead_regs:
            if _same_register_width(destination, dead_reg):
                candidates.append((insn, destination, dead_reg))
                break

    return candidates


def generate_dead_code_with_liveness(dead_regs: set[str], bits: int, size: int) -> list[str] | None:
    """Generate dead code that uses dead registers."""
    if not dead_regs:
        return None

    reg = random.choice(list(dead_regs))

    if bits == ARCH_BITS_64:
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
    "substitute_destination_register",
]
