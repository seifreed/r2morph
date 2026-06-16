"""Leaf helpers for register substitution analysis."""

from __future__ import annotations

import logging
import random
import re
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

logger = logging.getLogger(__name__)

REGISTER_CLASSES: dict[str, dict[str, list[str]]] = {
    "x86": {
        "gp32": ["eax", "ebx", "ecx", "edx", "esi", "edi"],
        "caller_saved": ["eax", "ecx", "edx"],
        "callee_saved": ["ebx", "esi", "edi"],
    },
    "x64": {
        "gp64": [
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
        ],
        "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
        "callee_saved": ["rbx", "r12", "r13", "r14", "r15"],
    },
    "arm": {
        "gp": ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
        "caller_saved": ["r0", "r1", "r2", "r3"],
        "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
    },
    "arm64": {
        "gp64": [
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
        "gp32": [
            "w0",
            "w1",
            "w2",
            "w3",
            "w4",
            "w5",
            "w6",
            "w7",
            "w8",
            "w9",
            "w10",
            "w11",
            "w12",
            "w13",
            "w14",
            "w15",
            "w16",
            "w17",
            "w18",
            "w19",
            "w20",
            "w21",
            "w22",
            "w23",
            "w24",
            "w25",
            "w26",
            "w27",
            "w28",
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
            "x30",
        ],
        "callee_saved": ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"],
    },
}

REGISTER_SIZES: dict[str, int] = {
    "al": 8,
    "bl": 8,
    "cl": 8,
    "dl": 8,
    "ah": 8,
    "bh": 8,
    "ch": 8,
    "dh": 8,
    "spl": 8,
    "bpl": 8,
    "sil": 8,
    "dil": 8,
    "r8b": 8,
    "r9b": 8,
    "r10b": 8,
    "r11b": 8,
    "r12b": 8,
    "r13b": 8,
    "r14b": 8,
    "r15b": 8,
    "ax": 16,
    "bx": 16,
    "cx": 16,
    "dx": 16,
    "sp": 16,
    "bp": 16,
    "si": 16,
    "di": 16,
    "r8w": 16,
    "r9w": 16,
    "r10w": 16,
    "r11w": 16,
    "r12w": 16,
    "r13w": 16,
    "r14w": 16,
    "r15w": 16,
    "eax": 32,
    "ebx": 32,
    "ecx": 32,
    "edx": 32,
    "esp": 32,
    "ebp": 32,
    "esi": 32,
    "edi": 32,
    "r8d": 32,
    "r9d": 32,
    "r10d": 32,
    "r11d": 32,
    "r12d": 32,
    "r13d": 32,
    "r14d": 32,
    "r15d": 32,
    "rax": 64,
    "rbx": 64,
    "rcx": 64,
    "rdx": 64,
    "rsp": 64,
    "rbp": 64,
    "rsi": 64,
    "rdi": 64,
    "r8": 64,
    "r9": 64,
    "r10": 64,
    "r11": 64,
    "r12": 64,
    "r13": 64,
    "r14": 64,
    "r15": 64,
}

_X86_REGISTER_FAMILIES: dict[str, list[str]] = {
    "a": ["al", "ah", "ax", "eax", "rax"],
    "b": ["bl", "bh", "bx", "ebx", "rbx"],
    "c": ["cl", "ch", "cx", "ecx", "rcx"],
    "d": ["dl", "dh", "dx", "edx", "rdx"],
    "si": ["sil", "si", "esi", "rsi"],
    "di": ["dil", "di", "edi", "rdi"],
    "sp": ["spl", "sp", "esp", "rsp"],
    "bp": ["bpl", "bp", "ebp", "rbp"],
}


def get_register_class(arch: str) -> dict[str, list[str]]:
    """Get register classes for architecture."""
    if arch in ["x86", "x64"]:
        arch_family = arch
    elif arch == "arm64":
        arch_family = "arm64"
    elif arch == "arm":
        arch_family = "arm"
    else:
        return {}
    return REGISTER_CLASSES.get(arch_family, {})


# Calls and system calls pass arguments / leave return values in registers by ABI,
# with no textual operand at the transfer. Renaming the exact register a transfer
# reads (argument) or whose value is read afterwards (return) silently corrupts it.
# The sets below are the canonical 64-bit registers each transfer reads (inputs) and
# leaves (outputs). x86 unions System V AMD64 and Microsoft x64; the 32-bit `int
# 0x80` extras (ebx/ecx/ebp) are folded in. ARM64 uses AAPCS / svc.
_SYSCALL_INPUT_REGISTERS = frozenset({"rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "rbx", "rcx", "rbp"})
_SYSCALL_OUTPUT_REGISTERS = frozenset({"rax"})
_SVC_INPUT_REGISTERS = frozenset({f"x{n}" for n in range(9)})
_SVC_OUTPUT_REGISTERS = frozenset({"x0"})
_CALL_INPUT_REGISTERS_X86 = frozenset({"rdi", "rsi", "rdx", "rcx", "r8", "r9"})
_CALL_INPUT_REGISTERS_ARM = frozenset({f"x{n}" for n in range(8)})
_CALL_OUTPUT_REGISTERS = frozenset({"rax", "x0"})

_SYSCALL_INT_VECTORS = frozenset({"0x80", "80h", "0x2e", "2eh"})
_PURE_WRITE_MNEMONICS = frozenset(
    {"mov", "movabs", "movzx", "movsx", "movq", "movd", "lea", "movz", "movk", "movn", "adr", "adrp", "ldr", "ldp"}
)
# Mnemonics that do not write a general-purpose register destination (compares,
# branches, stores, pushes). `pop` is excluded on purpose: it writes its operand.
_NO_DESTINATION_MNEMONICS = frozenset(
    {
        "cmp",
        "test",
        "push",
        "jmp",
        "je",
        "jne",
        "jz",
        "jnz",
        "jg",
        "jge",
        "jl",
        "jle",
        "ja",
        "jae",
        "jb",
        "jbe",
        "jo",
        "jno",
        "js",
        "jns",
        "jc",
        "jnc",
        "jp",
        "jnp",
        "call",
        "ret",
        "retn",
        "nop",
        "syscall",
        "sysenter",
        "int",
        "leave",
        "hlt",
        "cmn",
        "tst",
        "b",
        "bl",
        "blr",
        "br",
        "blx",
        "svc",
        "cbz",
        "cbnz",
        "tbz",
        "tbnz",
        "str",
        "stp",
        "stur",
        "strb",
        "strh",
        "sturb",
        "sturh",
    }
)


def _build_canonical_registers() -> dict[str, str]:
    """Map every register spelling to its canonical 64-bit identity."""
    family_base = {"a": "rax", "b": "rbx", "c": "rcx", "d": "rdx", "si": "rsi", "di": "rdi", "sp": "rsp", "bp": "rbp"}
    mapping: dict[str, str] = {}
    for key, members in _X86_REGISTER_FAMILIES.items():
        for member in members:
            mapping[member] = family_base[key]
    for num in range(8, 16):
        for suffix in ("", "d", "w", "b"):
            mapping[f"r{num}{suffix}"] = f"r{num}"
    for num in range(31):
        mapping[f"x{num}"] = f"x{num}"
        mapping[f"w{num}"] = f"x{num}"
    return mapping


_CANONICAL_REGISTER = _build_canonical_registers()
_REGISTER_TOKEN_RE = re.compile(r"\b(" + "|".join(sorted(_CANONICAL_REGISTER, key=len, reverse=True)) + r")\b")


def _register_tokens(text: str) -> list[str]:
    """Register spellings appearing in an operand string, in order."""
    return list(_REGISTER_TOKEN_RE.findall(text))


def _transfer_abi(disasm: str) -> tuple[frozenset[str], frozenset[str]] | None:
    """(inputs, outputs) canonical register sets for a call/syscall, else None."""
    tokens = disasm.split()
    if not tokens:
        return None
    mnemonic = tokens[0]
    if mnemonic in ("syscall", "sysenter"):
        return _SYSCALL_INPUT_REGISTERS, _SYSCALL_OUTPUT_REGISTERS
    if mnemonic == "int" and len(tokens) > 1 and tokens[1].rstrip(",") in _SYSCALL_INT_VECTORS:
        return _SYSCALL_INPUT_REGISTERS, _SYSCALL_OUTPUT_REGISTERS
    if mnemonic == "svc":
        return _SVC_INPUT_REGISTERS, _SVC_OUTPUT_REGISTERS
    if mnemonic == "call":
        return _CALL_INPUT_REGISTERS_X86, _CALL_OUTPUT_REGISTERS
    if mnemonic in ("bl", "blr", "blx"):
        return _CALL_INPUT_REGISTERS_ARM, _CALL_OUTPUT_REGISTERS
    return None


def _destination_register(disasm: str) -> str | None:
    """The register written by an instruction (first operand), or None."""
    parts = disasm.split(None, 1)
    if not parts:
        return None
    mnemonic = parts[0]
    if mnemonic in _NO_DESTINATION_MNEMONICS or mnemonic.startswith("b."):
        return None
    if len(parts) < 2:
        return None
    first_operand = parts[1].split(",", 1)[0].strip()
    if "[" in first_operand:  # memory destination writes memory, not a register
        return None
    tokens = _register_tokens(first_operand)
    return tokens[0] if tokens else None


def _source_registers(disasm: str) -> set[str]:
    """Registers read by an instruction (every operand register that is not a
    write-only destination)."""
    parts = disasm.split(None, 1)
    if len(parts) < 2:
        return set()
    tokens = set(_register_tokens(parts[1]))
    if parts[0] in _PURE_WRITE_MNEMONICS:
        destination = _destination_register(disasm)
        if destination is not None:
            tokens.discard(destination)
    return tokens


def abi_live_registers(instructions: list[dict[str, Any]]) -> set[str]:
    """Register tokens whose value a call/syscall consumes (argument, by the last
    write that reaches the transfer) or produces and is then read (return value).
    Renaming these would corrupt the transfer; everything else stays substitutable.
    A register written and overwritten before the transfer is dead and stays free
    (e.g. an early ``eax`` computation before ``mov rax, <nr>; syscall``)."""
    disasms = [insn.get("disasm", "").lower() for insn in instructions]
    unsafe: set[str] = set()
    total = len(disasms)
    for index, disasm in enumerate(disasms):
        transfer = _transfer_abi(disasm)
        if transfer is None:
            continue
        inputs, outputs = transfer

        # Inputs: the token that last writes each argument register, scanning back to
        # the previous transfer (which clobbers caller-saved registers).
        pending_inputs = set(inputs)
        for prior in range(index - 1, -1, -1):
            if _transfer_abi(disasms[prior]) is not None:
                break
            destination = _destination_register(disasms[prior])
            if destination is None:
                continue
            canonical = _CANONICAL_REGISTER.get(destination)
            if canonical in pending_inputs:
                unsafe.add(destination)
                pending_inputs.discard(canonical)
                if not pending_inputs:
                    break

        # Outputs: tokens that read the return register before it is redefined.
        pending_outputs = set(outputs)
        for later in range(index + 1, total):
            if not pending_outputs or _transfer_abi(disasms[later]) is not None:
                break
            for token in _source_registers(disasms[later]):
                if _CANONICAL_REGISTER.get(token) in pending_outputs:
                    unsafe.add(token)
            destination = _destination_register(disasms[later])
            redefined = _CANONICAL_REGISTER.get(destination) if destination is not None else None
            if redefined is not None and disasms[later].split(None, 1)[0] in _PURE_WRITE_MNEMONICS:
                pending_outputs.discard(redefined)
    return unsafe


def find_substitution_candidates(instructions: list[dict[str, Any]], arch: str) -> list[tuple[str, str]]:
    """Find valid register substitution opportunities."""
    register_classes = get_register_class(arch)
    if not register_classes:
        return []

    used_registers = set()
    for insn in instructions:
        disasm = insn.get("disasm", "").lower()
        for reg_class in register_classes.values():
            for reg in reg_class:
                if reg in disasm:
                    used_registers.add(reg)

    # Tokens whose value a call/syscall consumes or produces are live across the
    # transfer with no renameable operand; never rename them (source) and never
    # overwrite them with a substitution (target).
    abi_regs = abi_live_registers(instructions)
    caller_saved = set(register_classes.get("caller_saved", []))
    unused = sorted(caller_saved - used_registers - abi_regs)
    random.shuffle(unused)

    candidates = []
    for i, used_reg in enumerate(sorted((used_registers & caller_saved) - abi_regs)):
        if i < len(unused):
            candidates.append((used_reg, unused[i]))
    return candidates


def count_register_uses(instructions: list[dict[str, Any]], register: str) -> int:
    """Count how many times a register is used."""
    count = 0
    for insn in instructions:
        disasm = insn.get("disasm", "").lower()
        if register in disasm:
            count += 1
    return count


def is_safe_size_extension_substitution(disasm: str, orig_reg: str, subst_reg: str) -> bool:
    """Check if register substitution is safe for movzx/movsx instructions."""
    parts = disasm.split(",")
    if len(parts) < 2:
        return False

    dest = parts[0].split()[-1].strip()
    source = parts[1].strip()

    orig_size = REGISTER_SIZES.get(orig_reg, 0)
    subst_size = REGISTER_SIZES.get(subst_reg, 0)
    if orig_size == 0 or subst_size == 0:
        return False
    if orig_size != subst_size:
        logger.debug(
            f"Skipping {disasm}: {orig_reg}({orig_size}b) -> {subst_reg}({subst_size}b) size mismatch for movzx/movsx"
        )
        return False

    source_family = None
    orig_family = None
    subst_family = None
    for family, regs in _X86_REGISTER_FAMILIES.items():
        if source in regs:
            source_family = family
        if orig_reg in regs:
            orig_family = family
        if subst_reg in regs:
            subst_family = family

    if orig_reg == dest:
        if subst_family and orig_family and subst_family == orig_family:
            logger.debug(f"Skipping dest substitution {disasm}: {subst_reg} is in same family as {dest}")
            return False
    elif orig_reg == source:
        if subst_family and source_family and subst_family == source_family:
            logger.debug(
                f"Skipping source substitution {disasm}: {subst_reg} would be in same family as source {source}"
            )
            return False

    dest_mem_size = REGISTER_SIZES.get(dest, 0)
    source_mem_size = REGISTER_SIZES.get(source, 0)
    if dest_mem_size > 0 and source_mem_size > 0:
        if dest_mem_size < source_mem_size:
            logger.debug(
                f"Skipping size extension: dest size ({dest_mem_size}) must be >= source size ({source_mem_size})"
            )
            return False
        if dest_mem_size == source_mem_size:
            logger.debug(f"Skipping size extension: dest size ({dest_mem_size}) equals source size ({source_mem_size})")
            return False

    return True


def is_safe_lea_substitution(disasm: str, orig_reg: str, subst_reg: str) -> bool:
    """Check if register substitution is safe for LEA."""
    parts = disasm.split(",", 1)
    if len(parts) < 2:
        return False

    dest = parts[0].split()[-1].strip()
    calculation_part = parts[1].strip()

    if orig_reg == dest:
        return True

    if "[" in calculation_part and "]" in calculation_part:
        calc_inner = calculation_part.split("[")[1].split("]")[0]
        if re.search(r"\b" + re.escape(orig_reg) + r"\b", calc_inner):
            logger.debug(f"Skipping LEA substitution: {orig_reg} in address calculation of '{disasm}'")
            return False

    return True


def select_candidates(
    binary: Any,
    functions: list[dict[str, Any]],
    arch: str,
    probability: float,
    max_substitutions: int,
) -> list[tuple[dict, list[dict], list[tuple[str, str]]]]:
    """Select functions with substitution candidates."""
    result = []
    for func in functions:
        if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
            continue
        func_addr = func.get("offset", func.get("addr", 0))
        try:
            instructions = binary.get_function_disasm(func_addr)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
            continue
        candidates = find_substitution_candidates(instructions, arch)
        if not candidates:
            continue
        if random.random() > probability:
            continue
        num_substitutions = min(max_substitutions, len(candidates))
        selected = random.sample(candidates, num_substitutions)
        result.append((func, instructions, selected))
    return result


__all__ = [
    "REGISTER_CLASSES",
    "REGISTER_SIZES",
    "abi_live_registers",
    "count_register_uses",
    "find_substitution_candidates",
    "get_register_class",
    "is_safe_lea_substitution",
    "is_safe_size_extension_substitution",
    "select_candidates",
]
