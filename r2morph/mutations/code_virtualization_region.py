"""
Whole-function control-flow virtualization.

Where :mod:`code_virtualization_engine` virtualizes a single straight-line
register run, this module virtualizes an entire function whose every
instruction is a register op, a comparison, or a branch. The control flow is
lowered into the VM's own bytecode: comparisons capture the real RFLAGS into
a private slot, conditional/unconditional branches retarget the bytecode
pointer, and each terminator (``ret``/``syscall``) becomes a distinct VM exit
back to native code (any number of terminators is supported).

The VM never emulates flags by hand - a comparison runs the real ``cmp`` and
the interpreter stamps ``pushfq``/``popfq`` around the dispatch loop, so the
architectural condition codes are exactly reproduced for the branch.

A function that is not fully reducible to this model (a call, a memory
operand, an indirect or out-of-function branch, no terminator) yields
``None`` and is left untouched.
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
    """Per-instance opcode assignment, bytecode key, and register-slot layout.

    ``slot_perm`` is a per-instance bijection ``logical register index -> frame
    slot``: each architectural register spills to a shuffled slot rather than its
    ModR/M-ordered one, so a disassembler cannot label the context frame by
    reading it positionally and slot indices in the bytecode reveal no register.
    """

    __slots__ = ("opcodes", "xor_key", "junk_seed", "slot_perm")

    def __init__(self, opcodes: dict[str, int], xor_key: int, junk_seed: int, slot_perm: tuple[int, ...]) -> None:
        self.opcodes = opcodes
        self.xor_key = xor_key
        self.junk_seed = junk_seed
        self.slot_perm = slot_perm


class Region:
    """A lowered single-exit function ready to encode to VM bytecode.

    ``instructions`` is a flat list of VM items; branch items carry the index
    of their target item. ``exit_vaddr`` is the native terminator the VM jumps
    back to. ``op_keys`` is the set of interpreter handlers the region needs.
    """

    __slots__ = ("instructions", "exit_vaddr", "entry_vaddr", "op_keys", "body_ranges")

    def __init__(
        self,
        instructions: list[tuple[Any, ...]],
        exit_vaddr: int,
        entry_vaddr: int,
        op_keys: set[str],
        body_ranges: list[tuple[int, int]],
    ) -> None:
        self.instructions = instructions
        self.exit_vaddr = exit_vaddr  # default exit, used by the unknown-opcode guard
        self.entry_vaddr = entry_vaddr
        self.op_keys = op_keys
        self.body_ranges = body_ranges  # (addr, size) of each virtualized body instruction


def _register_operand(name: str) -> tuple[int, int] | None:
    if name in REGISTER_INDEX:
        return (REGISTER_INDEX[name], 64) if name != "rsp" else None
    if name in REGISTER32_INDEX:
        return (REGISTER32_INDEX[name], 32) if name != "esp" else None
    return None


def _decode_two_operand(disasm: str, mnemonic: str) -> tuple[int, int, bool, int] | None:
    """Decode ``<mnemonic> reg, reg|imm`` into (slot, value, is_immediate, width)."""
    parts = disasm.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != mnemonic or "," not in parts[1]:
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


def _decode_shift(disasm: str) -> tuple[str, int, int, int] | None:
    """Decode ``shl|shr|sar reg, imm8`` into (mnemonic, slot, count, width)."""
    parts = disasm.split(None, 1)
    if len(parts) != 2 or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in ("shl", "shr", "sar"):
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    dst = _register_operand(left)
    if dst is None:
        return None
    slot, width = dst
    try:
        count = int(right, 0)
    except ValueError:
        return None  # register/cl counts are out of scope
    if count < 0 or count > 63:
        return None
    return (mnemonic, slot, count, width)


def _decode_imul(disasm: str) -> tuple[int, int, int] | None:
    """Decode the two-operand register form ``imul reg, reg`` into (dst, src, width)."""
    parts = disasm.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "imul" or "," not in parts[1]:
        return None
    fields = parts[1].split(",")
    if len(fields) != 2:
        return None  # one- or three-operand forms are out of scope
    dst = _register_operand(fields[0].strip().lower())
    src = _register_operand(fields[1].strip().lower())
    if dst is None or src is None or dst[1] != src[1]:
        return None
    return (dst[0], src[0], dst[1])


def _op_key(item: tuple[Any, ...]) -> str | None:
    kind = item[0]
    if kind == "op":
        op: VirtualizedOp = item[1]
        return f"op_{op.mnemonic}_{'i' if op.is_immediate else 'r'}_{op.width}"
    if kind == "cmp":
        return f"cmp_{'i' if item[3] else 'r'}_{item[4]}"
    if kind == "test":
        return f"test_{'i' if item[3] else 'r'}_{item[4]}"
    if kind == "shift":
        return f"{item[1]}_{item[4]}"
    if kind == "imul":
        return f"imul_{item[3]}"
    if kind == "jmp":
        return "jmp"
    if kind == "jcc":
        return f"jcc_{item[1]}"
    if kind == "nop":
        return "nop"
    if kind == "exit":
        return f"exit_{item[1]}"
    return None


def _required_key(item: tuple[Any, ...]) -> str:
    """The handler key for an item that must have one (all but exit)."""
    key = _op_key(item)
    if key is None:
        raise ValueError(f"item has no handler key: {item[0]}")
    return key


def _classify(insn: dict[str, Any]) -> list[Any] | None:
    """Build the VM item for one body instruction, or ``None`` if unsupported."""
    kind = insn.get("type", "")
    text = insn.get("opcode", "")
    if kind == "nop":
        return ["nop"]
    if kind in ("mov", "add", "sub", "xor", "and", "or"):
        op = decode_instruction(text)
        return ["op", op] if op is not None else None
    if kind == "cmp":
        compare = _decode_two_operand(text, "cmp")
        return ["cmp", *compare] if compare is not None else None
    if kind == "acmp":
        test = _decode_two_operand(text, "test")
        return ["test", *test] if test is not None else None
    if kind in ("shl", "shr", "sar"):
        shift = _decode_shift(text)
        return ["shift", *shift] if shift is not None else None
    if kind == "mul":
        imul = _decode_imul(text)
        return ["imul", *imul] if imul is not None else None
    if kind == "jmp":
        return ["jmp", insn.get("jump", -1)]
    if kind == "cjmp":
        condition = _CONDITION.get(text.split(None, 1)[0].lower())
        return ["jcc", condition, insn.get("jump", -1)] if condition is not None else None
    return None


def extract_region(instructions: list[dict[str, Any]]) -> Region | None:
    """Lower a function's linear instruction list into a :class:`Region`.

    Returns ``None`` unless every instruction is a register op, comparison,
    ``nop``, in-function branch, or a terminator (``ret``/``syscall``). Any
    number of terminators is allowed; each becomes a distinct VM exit.
    """
    if not instructions:
        return None

    exit_addrs = sorted({insn["addr"] for insn in instructions if insn.get("type") in ("ret", "swi", "syscall")})
    if not exit_addrs:
        return None
    exit_set = set(exit_addrs)
    body = [insn for insn in instructions if insn["addr"] not in exit_set]
    if not body:
        return None

    # Phase 1: build items, recording each instruction's item index and storing
    # branch/fall-through targets as native addresses (resolved in phase 2). A
    # target that is a terminator address denotes that terminator's exit item.
    items: list[list[Any]] = []
    item_index_of: dict[int, int] = {}
    op_keys: set[str] = set()
    for insn in body:
        item = _classify(insn)
        if item is None:
            return None
        item_index_of[insn["addr"]] = len(items)
        items.append(item)
        key = _op_key(tuple(item))
        if key is not None:
            op_keys.add(key)
        # Fall-through into a terminator (everything except an unconditional jmp).
        next_addr = insn["addr"] + insn.get("size", 0)
        if item[0] != "jmp" and next_addr in exit_set:
            items.append(["jmp", next_addr])
            op_keys.add("jmp")

    exit_index_of: dict[int, int] = {}
    for addr in exit_addrs:
        exit_index_of[addr] = len(items)
        items.append(["exit", addr])
        op_keys.add(f"exit_{addr}")
    if any(item[0] == "jmp" for item in items):
        op_keys.add("jmp")

    def resolve(target: int) -> int | None:
        if target in exit_index_of:
            return exit_index_of[target]
        return item_index_of.get(target)

    # Phase 2: resolve branch target addresses to item indices.
    for item in items:
        if item[0] == "jmp":
            resolved = resolve(item[1])
            if resolved is None:
                return None
            item[1] = resolved
        elif item[0] == "jcc":
            resolved = resolve(item[2])
            if resolved is None:
                return None
            item[2] = resolved

    body_ranges = [(insn["addr"], insn.get("size", 0)) for insn in body]
    return Region([tuple(item) for item in items], exit_addrs[0], body[0]["addr"], op_keys, body_ranges)


def build_region_scheme(region: Region, rng: random.Random) -> RegionScheme:
    """Assign each handler a dense opcode index plus a bytecode key.

    Opcodes are a per-instance permutation of ``0..N-1`` (N = handler count):
    they index the dispatch table directly, so two builds still share no
    opcode->operation mapping (the permutation differs), but the table stays
    N entries wide instead of a full 256.
    """
    keys = sorted(region.op_keys)
    indices = rng.sample(range(len(keys)), len(keys))
    slot_perm = tuple(rng.sample(range(len(GP_REGISTERS)), len(GP_REGISTERS)))
    return RegionScheme(dict(zip(keys, indices, strict=True)), rng.randrange(1, 256), rng.randrange(1 << 31), slot_perm)


# Semantically-neutral instructions used as per-instance junk. They are emitted
# only after a handler's terminating jump (unreachable), so they never execute;
# they make each VM instance structurally distinct to defeat handler signatures.
_JUNK_TEMPLATES: tuple[str, ...] = (
    "nop",
    "mov r10, r11",
    "xor r10, r11",
    "and r10, r11",
    "or r11, r10",
    "xchg r8, r9",
    "add r10, {small}",
    "sub r11, {small}",
    "lea rax, [rax + {small}]",
    "ror r10, {shift}",
)


def _junk_asm(rng: random.Random) -> str:
    """A short run of unreachable junk instructions for handler diversification.

    Operands are register-to-register or small immediates only, so every
    template always assembles - a junk instruction that failed to assemble
    would abort the whole virtualization.
    """
    lines = []
    for _ in range(rng.randint(0, 4)):
        template = rng.choice(_JUNK_TEMPLATES)
        lines.append("  " + template.format(small=rng.randint(1, 127), shift=rng.randint(1, 31)) + "\n")
    return "".join(lines)


def _item_size(item: tuple[Any, ...]) -> int:
    kind = item[0]
    if kind == "op":
        op: VirtualizedOp = item[1]
        if op.is_immediate:
            return 2 + (8 if op.width == 64 else 4)
        return 3
    if kind in ("cmp", "test"):
        return 2 + (8 if item[4] == 64 else 4) if item[3] else 3
    if kind in ("shift", "imul"):
        return 3
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

    slot_of = scheme.slot_perm  # logical register index -> shuffled frame slot
    plain = bytearray()

    def emit_opcode(opcode: int) -> None:
        # The opcode byte is masked with its own stream position, so the same
        # operation does not encode to the same byte twice and a single-byte XOR
        # of the whole blob no longer exposes the opcode stream. The dispatcher
        # subtracts the position back out before decoding.
        plain.append(opcode ^ (len(plain) & 0xFF))

    for item in region.instructions:
        kind = item[0]
        if kind == "op":
            op = item[1]
            emit_opcode(scheme.opcodes[_required_key(item)])
            plain.append(slot_of[op.dst_index])
            if op.is_immediate:
                plain += struct.pack("<q" if op.width == 64 else "<i", op.value)
            else:
                plain.append(slot_of[op.value])
        elif kind in ("cmp", "test"):
            _, slot, value, is_imm, width = item
            emit_opcode(scheme.opcodes[_required_key(item)])
            plain.append(slot_of[slot])
            if is_imm:
                plain += struct.pack("<q" if width == 64 else "<i", value)
            else:
                plain.append(slot_of[value])
        elif kind == "shift":
            _, _mnemonic, slot, count, _width = item
            emit_opcode(scheme.opcodes[_required_key(item)])
            plain.append(slot_of[slot])
            plain.append(count)
        elif kind == "imul":
            _, dst, src, _width = item
            emit_opcode(scheme.opcodes[_required_key(item)])
            plain.append(slot_of[dst])
            plain.append(slot_of[src])
        elif kind == "jmp":
            emit_opcode(scheme.opcodes["jmp"])
            plain += struct.pack("<i", offsets[item[1]])
        elif kind == "jcc":
            emit_opcode(scheme.opcodes[_required_key(item)])
            plain += struct.pack("<i", offsets[item[2]])
        elif kind == "nop":
            emit_opcode(scheme.opcodes["nop"])
        elif kind == "exit":
            emit_opcode(scheme.opcodes[_required_key(item)])
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


def _compare_handler_asm(handler_key: str, key: int, key_qword: str, key_dword: str) -> str:
    """Assembly body for a cmp/test handler (sets and captures flags only)."""
    mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
    if mode == "i" and width == 64:
        body += f"  mov rax, qword ptr [rsi+2]\n  mov r10, {key_qword}\n  xor rax, r10\n  mov r9, qword ptr [rsp+r8*8]\n  {mnemonic} r9, rax\n"
        advance = 10
    elif mode == "i":
        body += f"  mov eax, dword ptr [rsi+2]\n  mov r11d, {key_dword}\n  xor eax, r11d\n  mov r9d, dword ptr [rsp+r8*8]\n  {mnemonic} r9d, eax\n"
        advance = 6
    else:
        body += f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
        if width == 64:
            body += f"  mov rax, qword ptr [rsp+r9*8]\n  mov r10, qword ptr [rsp+r8*8]\n  {mnemonic} r10, rax\n"
        else:
            body += f"  mov eax, dword ptr [rsp+r9*8]\n  mov r10d, dword ptr [rsp+r8*8]\n  {mnemonic} r10d, eax\n"
        advance = 3
    return body + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _shift_handler_asm(handler_key: str, key: int) -> str:
    """Assembly body for a shl/shr/sar handler (count is an immediate in cl)."""
    mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n" f"  movzx ecx, byte ptr [rsi+2]\n  xor cl, {key}\n"
    if width == 64:
        body += f"  mov rax, qword ptr [rsp+r8*8]\n  {mnemonic} rax, cl\n"
    else:
        body += f"  mov eax, dword ptr [rsp+r8*8]\n  {mnemonic} eax, cl\n"
    return (
        body
        + f"  mov qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _imul_handler_asm(handler_key: str, key: int) -> str:
    """Assembly body for a two-operand register imul handler."""
    width = int(handler_key.split("_")[1])
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n" f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
    if width == 64:
        body += "  mov rax, qword ptr [rsp+r8*8]\n  imul rax, qword ptr [rsp+r9*8]\n"
    else:
        body += "  mov eax, dword ptr [rsp+r8*8]\n  imul eax, dword ptr [rsp+r9*8]\n"
    return (
        body
        + f"  mov qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _interpreter_asm(region: Region, scheme: RegionScheme) -> str:
    key = scheme.xor_key
    key_qword = hex((key * _QWORD_BROADCAST) & 0xFFFFFFFFFFFFFFFF)
    key_dword = hex((key * _DWORD_BROADCAST) & 0xFFFFFFFF)
    retarget = (
        f"  mov eax, dword ptr [rsi+1]\n  xor eax, {key_dword}\n"
        "  lea r9, [rip+bytecode]\n  add r9, rax\n  mov rsi, r9\n  jmp vm_dispatch\n"
    )

    slot = scheme.slot_perm  # logical register index -> shuffled frame slot
    lines = [f"vm_entry:\n  sub rsp, {_FRAME_SIZE}\n"]
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov qword ptr [rsp+{slot[index] * 8}], {name}\n")
    lines.append(
        f"  lea rax, [rsp+{_FRAME_SIZE}]\n  mov qword ptr [rsp+{slot[RSP_INDEX] * 8}], rax\n"
        "  lea rsi, [rip+bytecode]\n  mov r15, rsi\n"
        # Indirect, opcode-indexed dispatch: the decrypted opcode byte indexes a
        # per-handler offset table, so there is no linear comparison ladder for a
        # disassembler or automated devirtualizer to pattern-match. r13/r14/r15 are
        # spilled context slots, free to clobber between handlers (r15 holds the
        # bytecode base for the whole run).
        "vm_dispatch:\n"
        # Undo the opcode byte's position mask (encoder XORed it with rsi-base).
        "  mov r13, rsi\n  sub r13, r15\n"
        "  movzx eax, byte ptr [rsi]\n"
        f"  xor al, {key}\n  xor al, r13b\n"
        f"  cmp al, {len(scheme.opcodes)}\n  jae vm_exit\n"
        # Base-independent indirect dispatch: each table entry is a 32-bit signed
        # offset from vm_table to its handler, so the jump survives rebasing/ASLR
        # exactly like the rel32 jumps the rest of the blob relies on.
        "  lea r14, [rip+vm_table]\n  movsxd rax, dword ptr [r14+rax*4]\n  add rax, r14\n  jmp rax\n"
    )

    reload_seq = "".join(
        f"  mov {name}, qword ptr [rsp+{slot[index] * 8}]\n" for index, name in enumerate(GP_REGISTERS) if name != "rsp"
    )

    junk_rng = random.Random(scheme.junk_seed)
    for handler_key in sorted(scheme.opcodes):
        lines.append(f"H_{handler_key}:\n")
        if handler_key.startswith("op_"):
            lines.append(_op_handler_asm(handler_key, key, key_qword, key_dword))
        elif handler_key.startswith(("cmp_", "test_")):
            lines.append(_compare_handler_asm(handler_key, key, key_qword, key_dword))
        elif handler_key.startswith(("shl_", "shr_", "sar_")):
            lines.append(_shift_handler_asm(handler_key, key))
        elif handler_key.startswith("imul_"):
            lines.append(_imul_handler_asm(handler_key, key))
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
        elif handler_key.startswith("exit_"):
            exit_addr = int(handler_key.split("_", 1)[1])
            lines.append(f"{reload_seq}  add rsp, {_FRAME_SIZE}\n  jmp {hex(exit_addr)}\n")
        # Junk after the handler's terminating jump - unreachable, never runs.
        lines.append(_junk_asm(junk_rng))

    # Unknown-opcode guard: an out-of-range index (bounds-checked above) restores
    # state and leaves through the default exit, so a corrupt stream cannot
    # transfer control out of the VM. The table holds one entry per handler.
    index_to_label = {index: f"H_{handler_key}" for handler_key, index in scheme.opcodes.items()}
    table = "".join(
        f"  .long {index_to_label.get(index, 'vm_exit')} - vm_table\n" for index in range(len(scheme.opcodes))
    )
    lines.append(
        f"vm_exit:\n{reload_seq}  add rsp, {_FRAME_SIZE}\n  jmp {hex(region.exit_vaddr)}\n"
        f"vm_table:\n{table}bytecode:\n"
    )
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
