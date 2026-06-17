"""
Whole-function control-flow virtualization.

Where :mod:`code_virtualization_engine` virtualizes a single straight-line
register run, this module virtualizes an entire single-exit function whose
every instruction is a register op, a comparison, or a branch. The control
flow is lowered into the VM's own bytecode: comparisons capture the real
RFLAGS into a private slot, conditional/unconditional branches retarget the
bytecode pointer, and the one terminator (``ret``/``syscall``) becomes a VM
exit back to native code.

The VM never emulates flags by hand - a comparison runs the real ``cmp`` and
the interpreter stamps ``pushfq``/``popfq`` around the dispatch loop, so the
architectural condition codes are exactly reproduced for the branch.

A function that is not fully reducible to this model (a call, a memory
operand, an indirect or out-of-function branch, more than one terminator)
yields ``None`` and is left untouched.
"""

from __future__ import annotations

import logging
import random
import struct
from typing import Any

from r2morph.mutations.code_virtualization_engine import (
    GP_REGISTERS,
    REGISTER32_INDEX,
    REGISTER_INDEX,
    RSP_INDEX,
    VirtualizedOp,
    decode_instruction,
)

logger = logging.getLogger(__name__)

# Stack frame: 16 context slots in [0x00, 0x80), the captured RFLAGS at 0x80,
# and the System V red zone preserved in [0x100, 0x180).
_FRAME_SIZE = 0x180
_FLAGS_OFFSET = 0x80
_QWORD_BROADCAST = 0x0101010101010101
_DWORD_BROADCAST = 0x01010101

# r2 branch mnemonic -> the native conditional jump the interpreter emits.
_CONDITION: dict[str, str] = {
    "je": "je",
    "jz": "je",
    "jne": "jne",
    "jnz": "jne",
    "jl": "jl",
    "jnge": "jl",
    "jge": "jge",
    "jnl": "jge",
    "jg": "jg",
    "jnle": "jg",
    "jle": "jle",
    "jng": "jle",
    "jb": "jb",
    "jc": "jb",
    "jnae": "jb",
    "jae": "jae",
    "jnc": "jae",
    "jnb": "jae",
    "jbe": "jbe",
    "jna": "jbe",
    "ja": "ja",
    "jnbe": "ja",
    "js": "js",
    "jns": "jns",
    "jo": "jo",
    "jno": "jno",
    "jp": "jp",
    "jpe": "jp",
    "jnp": "jnp",
    "jpo": "jnp",
}


class RegionScheme:
    """Per-instance opcode assignment and bytecode key for a region VM."""

    __slots__ = ("opcodes", "xor_key")

    def __init__(self, opcodes: dict[str, int], xor_key: int) -> None:
        self.opcodes = opcodes
        self.xor_key = xor_key


class Region:
    """A lowered single-exit function ready to encode to VM bytecode.

    ``instructions`` is a flat list of VM items; branch items carry the index
    of their target item. ``exit_vaddr`` is the native terminator the VM jumps
    back to. ``op_keys`` is the set of interpreter handlers the region needs.
    """

    __slots__ = ("instructions", "exit_vaddr", "entry_vaddr", "op_keys")

    def __init__(
        self,
        instructions: list[tuple[Any, ...]],
        exit_vaddr: int,
        entry_vaddr: int,
        op_keys: set[str],
    ) -> None:
        self.instructions = instructions
        self.exit_vaddr = exit_vaddr
        self.entry_vaddr = entry_vaddr
        self.op_keys = op_keys


def _register_operand(name: str) -> tuple[int, int] | None:
    if name in REGISTER_INDEX:
        return (REGISTER_INDEX[name], 64) if name != "rsp" else None
    if name in REGISTER32_INDEX:
        return (REGISTER32_INDEX[name], 32) if name != "esp" else None
    return None


def _decode_compare(disasm: str) -> tuple[int, int, bool, int] | None:
    """Decode ``cmp reg, reg|imm`` into (slot, value, is_immediate, width)."""
    parts = disasm.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "cmp" or "," not in parts[1]:
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    dst = _register_operand(left)
    if dst is None:
        return None
    slot, width = dst
    src = _register_operand(right)
    if src is not None:
        if src[1] != width:
            return None
        return (slot, src[0], False, width)
    if any(marker in right for marker in ("[", "]", "rip", ":", "ptr")):
        return None
    try:
        immediate = int(right, 0)
    except ValueError:
        return None
    bound = 2 ** (width - 1)
    if immediate < -bound or immediate > bound - 1:
        return None
    return (slot, immediate, True, width)


def _op_key(item: tuple[Any, ...]) -> str | None:
    kind = item[0]
    if kind == "op":
        op: VirtualizedOp = item[1]
        return f"op_{op.mnemonic}_{'i' if op.is_immediate else 'r'}_{op.width}"
    if kind == "cmp":
        return f"cmp_{'i' if item[3] else 'r'}_{item[4]}"
    if kind == "jmp":
        return "jmp"
    if kind == "jcc":
        return f"jcc_{item[1]}"
    if kind == "nop":
        return "nop"
    return None


def extract_region(instructions: list[dict[str, Any]]) -> Region | None:
    """Lower a function's linear instruction list into a :class:`Region`.

    Returns ``None`` unless the function has exactly one terminator and every
    other instruction is a register op, comparison, ``nop``, or in-function
    branch.
    """
    if not instructions:
        return None

    terminators = [insn for insn in instructions if insn.get("type") in ("ret", "swi", "syscall")]
    if len(terminators) != 1:
        return None
    exit_vaddr = terminators[0]["addr"]
    body = [insn for insn in instructions if insn["addr"] != exit_vaddr]
    if not body:
        return None

    # Phase 1: build items, remembering each instruction's item index and the
    # native target address of every branch (resolved against item indices in
    # phase 2). Branch targets are stored as addresses; ``exit_vaddr`` denotes
    # the synthetic trailing exit item.
    items: list[list[Any]] = []
    item_index_of: dict[int, int] = {}
    op_keys: set[str] = set()
    for insn in body:
        kind = insn.get("type", "")
        text = insn.get("opcode", "")
        next_addr = insn["addr"] + insn.get("size", 0)
        item_index_of[insn["addr"]] = len(items)
        if kind == "nop":
            items.append(["nop"])
            if next_addr == exit_vaddr:
                items.append(["jmp", exit_vaddr])
        elif kind in ("mov", "add", "sub", "xor", "and", "or"):
            op = decode_instruction(text)
            if op is None:
                return None
            items.append(["op", op])
            if next_addr == exit_vaddr:
                items.append(["jmp", exit_vaddr])
        elif kind == "cmp":
            compare = _decode_compare(text)
            if compare is None:
                return None
            items.append(["cmp", *compare])
            if next_addr == exit_vaddr:
                items.append(["jmp", exit_vaddr])
        elif kind == "jmp":
            items.append(["jmp", insn.get("jump", -1)])
        elif kind == "cjmp":
            condition = _CONDITION.get(text.split(None, 1)[0].lower())
            if condition is None:
                return None
            items.append(["jcc", condition, insn.get("jump", -1)])
            if next_addr == exit_vaddr:
                items.append(["jmp", exit_vaddr])
        else:
            return None
        key = _op_key(tuple(items[-1]))
        if key is not None:
            op_keys.add(key)

    exit_index = len(items)
    items.append(["exit"])
    op_keys.add("exit")
    if any(item[0] == "jmp" for item in items):
        op_keys.add("jmp")

    # Phase 2: resolve branch target addresses to item indices.
    for item in items:
        if item[0] == "jmp":
            target = exit_index if item[1] == exit_vaddr else item_index_of.get(item[1])
            if target is None:
                return None
            item[1] = target
        elif item[0] == "jcc":
            target = exit_index if item[2] == exit_vaddr else item_index_of.get(item[2])
            if target is None:
                return None
            item[2] = target

    return Region([tuple(item) for item in items], exit_vaddr, body[0]["addr"], op_keys)


def build_region_scheme(region: Region, rng: random.Random) -> RegionScheme:
    """Assign each needed handler a distinct random opcode byte plus a key."""
    keys = sorted(region.op_keys)
    distinct = rng.sample(range(1, 256), len(keys))
    return RegionScheme(dict(zip(keys, distinct, strict=True)), rng.randrange(1, 256))


def _item_size(item: tuple[Any, ...]) -> int:
    kind = item[0]
    if kind == "op":
        op: VirtualizedOp = item[1]
        if op.is_immediate:
            return 2 + (8 if op.width == 64 else 4)
        return 3
    if kind == "cmp":
        return 2 + (8 if item[4] == 64 else 4) if item[3] else 3
    if kind in ("jmp", "jcc"):
        return 5
    return 1  # nop, exit


def encode_region(region: Region, scheme: RegionScheme) -> bytes:
    """Two-pass lowering: assign offsets, emit, then XOR-encrypt."""
    offsets: list[int] = []
    cursor = 0
    for item in region.instructions:
        offsets.append(cursor)
        cursor += _item_size(item)

    plain = bytearray()
    for item in region.instructions:
        kind = item[0]
        if kind == "op":
            op = item[1]
            plain.append(scheme.opcodes[_op_key(item)])
            plain.append(op.dst_index)
            if op.is_immediate:
                plain += struct.pack("<q" if op.width == 64 else "<i", op.value)
            else:
                plain.append(op.value)
        elif kind == "cmp":
            _, slot, value, is_imm, width = item
            plain.append(scheme.opcodes[_op_key(item)])
            plain.append(slot)
            if is_imm:
                plain += struct.pack("<q" if width == 64 else "<i", value)
            else:
                plain.append(value)
        elif kind == "jmp":
            plain.append(scheme.opcodes["jmp"])
            plain += struct.pack("<i", offsets[item[1]])
        elif kind == "jcc":
            plain.append(scheme.opcodes[_op_key(item)])
            plain += struct.pack("<i", offsets[item[2]])
        elif kind == "nop":
            plain.append(scheme.opcodes["nop"])
        elif kind == "exit":
            plain.append(scheme.opcodes["exit"])
    key = scheme.xor_key
    return bytes(byte ^ key for byte in plain)


def _op_handler_asm(handler_key: str, key: int, key_qword: str, key_dword: str) -> str:
    """Assembly body for an arithmetic/mov handler (decrypts, applies, captures flags)."""
    _, mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
    if is_immediate and width == 64:
        body += f"  mov rax, qword ptr [rsi+2]\n  mov r10, {key_qword}\n  xor rax, r10\n"
        advance = 10
    elif is_immediate:
        body += f"  mov eax, dword ptr [rsi+2]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
        advance = 6
    else:
        body += f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
        body += "  mov rax, qword ptr [rsp+r9*8]\n" if width == 64 else "  mov eax, dword ptr [rsp+r9*8]\n"
        advance = 3
    if mnemonic == "mov":
        body += "  mov qword ptr [rsp+r8*8], rax\n"
    elif width == 64:
        body += f"  {mnemonic} qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
    else:
        body += (
            f"  mov r11d, dword ptr [rsp+r8*8]\n  {mnemonic} r11d, eax\n"
            f"  mov qword ptr [rsp+r8*8], r11\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        )
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _cmp_handler_asm(handler_key: str, key: int, key_qword: str, key_dword: str) -> str:
    """Assembly body for a comparison handler (sets and captures flags only)."""
    _, mode, width_text = handler_key.split("_")
    width = int(width_text)
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
    if mode == "i" and width == 64:
        body += f"  mov rax, qword ptr [rsi+2]\n  mov r10, {key_qword}\n  xor rax, r10\n  mov r9, qword ptr [rsp+r8*8]\n  cmp r9, rax\n"
        advance = 10
    elif mode == "i":
        body += f"  mov eax, dword ptr [rsi+2]\n  mov r11d, {key_dword}\n  xor eax, r11d\n  mov r9d, dword ptr [rsp+r8*8]\n  cmp r9d, eax\n"
        advance = 6
    else:
        body += f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
        if width == 64:
            body += "  mov rax, qword ptr [rsp+r9*8]\n  mov r10, qword ptr [rsp+r8*8]\n  cmp r10, rax\n"
        else:
            body += "  mov eax, dword ptr [rsp+r9*8]\n  mov r10d, dword ptr [rsp+r8*8]\n  cmp r10d, eax\n"
        advance = 3
    return body + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _interpreter_asm(region: Region, scheme: RegionScheme) -> str:
    key = scheme.xor_key
    key_qword = hex((key * _QWORD_BROADCAST) & 0xFFFFFFFFFFFFFFFF)
    key_dword = hex((key * _DWORD_BROADCAST) & 0xFFFFFFFF)
    retarget = (
        f"  mov eax, dword ptr [rsi+1]\n  xor eax, {key_dword}\n"
        "  lea r9, [rip+bytecode]\n  add r9, rax\n  mov rsi, r9\n  jmp vm_dispatch\n"
    )

    lines = [f"vm_entry:\n  sub rsp, {_FRAME_SIZE}\n"]
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov qword ptr [rsp+{index * 8}], {name}\n")
    lines.append(
        f"  lea rax, [rsp+{_FRAME_SIZE}]\n  mov qword ptr [rsp+{RSP_INDEX * 8}], rax\n"
        "  lea rsi, [rip+bytecode]\n"
        "vm_dispatch:\n  movzx eax, byte ptr [rsi]\n"
        f"  xor al, {key}\n"
    )
    for handler_key in sorted(scheme.opcodes):
        lines.append(f"  cmp al, {scheme.opcodes[handler_key]}\n  je H_{handler_key}\n")
    lines.append("  jmp vm_exit\n")

    for handler_key in sorted(scheme.opcodes):
        lines.append(f"H_{handler_key}:\n")
        if handler_key.startswith("op_"):
            lines.append(_op_handler_asm(handler_key, key, key_qword, key_dword))
        elif handler_key.startswith("cmp_"):
            lines.append(_cmp_handler_asm(handler_key, key, key_qword, key_dword))
        elif handler_key == "jmp":
            lines.append(retarget)
        elif handler_key.startswith("jcc_"):
            native = handler_key.split("_", 1)[1]
            lines.append(
                f"  push qword ptr [rsp+{_FLAGS_OFFSET}]\n  popfq\n  {native} T_{handler_key}\n"
                "  add rsi, 5\n  jmp vm_dispatch\n"
                f"T_{handler_key}:\n{retarget}"
            )
        elif handler_key == "nop":
            lines.append("  add rsi, 1\n  jmp vm_dispatch\n")
        elif handler_key == "exit":
            lines.append("  jmp vm_exit\n")

    lines.append("vm_exit:\n")
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov {name}, qword ptr [rsp+{index * 8}]\n")
    lines.append(f"  add rsp, {_FRAME_SIZE}\n  jmp {hex(region.exit_vaddr)}\nbytecode:\n")
    return "".join(lines)


def build_region_blob(region: Region, cave_vaddr: int, scheme: RegionScheme) -> bytes | None:
    """Assemble the region interpreter at ``cave_vaddr`` and append its bytecode."""
    try:
        import keystone
    except ImportError:
        logger.warning("keystone unavailable; cannot virtualize region")
        return None
    try:
        engine = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, _ = engine.asm(_interpreter_asm(region, scheme), cave_vaddr)
    except keystone.KsError as exc:
        logger.debug("Region interpreter assembly failed: %s", exc)
        return None
    if not encoding:
        return None
    return bytes(encoding) + encode_region(region, scheme)
