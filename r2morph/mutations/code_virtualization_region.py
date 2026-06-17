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
    RSP_INDEX,
    VirtualizedOp,
    decode_instruction,
    pack_immediate,
)
from r2morph.mutations.code_virtualization_region_decoders import (
    _decode_cmp_mem,
    _decode_imul,
    _decode_incdec,
    _decode_lea,
    _decode_lea_indexed,
    _decode_memory_mov,
    _decode_movx,
    _decode_op_mem,
    _decode_op_mem_indexed,
    _decode_op_memdst,
    _decode_riprel_mov,
    _decode_shift,
    _decode_two_operand,
)
from r2morph.mutations.code_virtualization_region_handlers import (
    _FLAGS_OFFSET,
    _FRAME_SIZE,
    _cmp_memory_handler_asm,
    _compare_handler_asm,
    _imul_handler_asm,
    _incdec_handler_asm,
    _lea_handler_asm,
    _lea_indexed_handler_asm,
    _memory_handler_asm,
    _movx_handler_asm,
    _movx_indexed_handler_asm,
    _op_handler_asm,
    _op_mem_indexed_handler_asm,
    _op_memdst_handler_asm,
    _op_memory_handler_asm,
    _riprel_handler_asm,
    _shift_handler_asm,
)

logger = logging.getLogger(__name__)

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
    """Per-instance handler layout, bytecode key, and register-slot layout.

    ``dup`` maps each handler key to the tuple of dense opcode indices that
    decode to it: an operation gets one or more interchangeable handler
    instances (each emitted with its own junk), so the opcode->operation map is
    not one-to-one and the same operation can appear as different opcodes in the
    stream. ``slot_perm`` is a per-instance bijection ``logical register index
    -> frame slot``: each register spills to a shuffled slot rather than its
    ModR/M-ordered one, so the context frame cannot be labelled positionally and
    slot indices in the bytecode reveal no register.
    """

    __slots__ = ("dup", "xor_key", "junk_seed", "slot_perm")

    def __init__(
        self, dup: dict[str, tuple[int, ...]], xor_key: int, junk_seed: int, slot_perm: tuple[int, ...]
    ) -> None:
        self.dup = dup
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


def _op_key(item: tuple[Any, ...]) -> str | None:
    kind = item[0]
    if kind == "lea":
        return "lea"
    if kind == "learip":
        return "learip"
    if kind == "leaidx":
        return "leaidx"
    if kind == "opmemidx":
        return f"opmemidx_{item[1]}_{item[7]}"
    if kind == "incdec":
        return f"incdec_{item[1]}_{item[3]}"
    if kind == "movx":
        return f"movx_{item[1]}_{item[2]}_{item[3]}"
    if kind == "movxidx":
        return f"movxidx_{item[1]}_{item[2]}_{item[3]}"
    if kind in ("load", "store"):
        return f"{kind}_{item[4]}"
    if kind in ("riprel_load", "riprel_store"):
        return f"{kind}_{item[3]}"
    if kind == "cmpmem":
        return f"cmpmem_{item[4]}"
    if kind == "cmpriprel":
        return f"cmpriprel_{item[3]}"
    if kind == "opmem":
        return f"opmem_{item[1]}_{item[5]}"
    if kind == "opriprel":
        return f"opriprel_{item[1]}_{item[4]}"
    if kind == "opmemdst":
        return f"opmemdst_{item[1]}_{item[5]}"
    if kind == "opmemdstrip":
        return f"opmemdstrip_{item[1]}_{item[4]}"
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
        if op is not None:
            return ["op", op]
        if kind == "mov":
            memory = _decode_memory_mov(text)
            if memory is not None:
                return [*memory]
            riprel = _decode_riprel_mov(text, insn.get("addr", 0), insn.get("size", 0))
            if riprel is not None:
                return [*riprel]
            movx = _decode_movx(text)
            return [*movx] if movx is not None else None
        incdec = _decode_incdec(text)
        if incdec is not None:
            return [*incdec]
        op_mem = _decode_op_mem(text, kind, insn.get("addr", 0), insn.get("size", 0))
        if op_mem is not None:
            return [*op_mem]
        op_memdst = _decode_op_memdst(text, kind, insn.get("addr", 0), insn.get("size", 0))
        if op_memdst is not None:
            return [*op_memdst]
        op_mem_idx = _decode_op_mem_indexed(text, kind)
        return [*op_mem_idx] if op_mem_idx is not None else None
    if kind == "cmp":
        compare = _decode_two_operand(text, "cmp")
        if compare is not None:
            return ["cmp", *compare]
        memory_cmp = _decode_cmp_mem(text, insn.get("addr", 0), insn.get("size", 0))
        return [*memory_cmp] if memory_cmp is not None else None
    if kind == "acmp":
        test = _decode_two_operand(text, "test")
        return ["test", *test] if test is not None else None
    if kind in ("shl", "shr", "sar"):
        shift = _decode_shift(text)
        return ["shift", *shift] if shift is not None else None
    if kind == "mul":
        imul = _decode_imul(text)
        return ["imul", *imul] if imul is not None else None
    if kind == "lea":
        lea = _decode_lea(text, insn.get("addr", 0), insn.get("size", 0))
        if lea is not None:
            return [*lea]
        lea_indexed = _decode_lea_indexed(text)
        return [*lea_indexed] if lea_indexed is not None else None
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
    # Give each handler one or two interchangeable instances; the total stays
    # within a byte so opcodes still index the table directly.
    multiplicity = {key: rng.randint(1, 2) for key in keys}
    total = sum(multiplicity.values())
    indices = rng.sample(range(total), total)
    dup: dict[str, tuple[int, ...]] = {}
    cursor = 0
    for key in keys:
        count = multiplicity[key]
        dup[key] = tuple(indices[cursor : cursor + count])
        cursor += count
    slot_perm = tuple(rng.sample(range(len(GP_REGISTERS)), len(GP_REGISTERS)))
    return RegionScheme(dup, rng.randrange(1, 256), rng.randrange(1 << 31), slot_perm)


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


# Live junk emitted at a handler's entry, so it actually executes and makes
# duplicate handlers differ in reachable code, not only in the unreachable tail.
# It touches only rbx/rbp/r12, which hold no live interpreter state (every GP
# register is spilled to the frame, and the dispatch loop only keeps rsi/rsp/r15
# live); flag effects are irrelevant at entry, where the captured flags are not
# yet set and a branch handler reloads them from the frame slot.
_LIVE_JUNK_TEMPLATES: tuple[str, ...] = (
    "mov rbx, rbp",
    "xor rbx, r12",
    "and rbp, r12",
    "or r12, rbx",
    "xchg rbx, rbp",
    "add r12, {small}",
    "sub rbx, {small}",
    "lea rbp, [rbp + {small}]",
    "ror r12, {shift}",
)


def _live_junk_asm(rng: random.Random) -> str:
    """A short run of reachable, state-neutral junk for the head of a handler."""
    lines = []
    for _ in range(rng.randint(0, 3)):
        template = rng.choice(_LIVE_JUNK_TEMPLATES)
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
    if kind in ("load", "store"):
        return 7  # opcode + reg slot + base slot + 4-byte displacement
    if kind in ("riprel_load", "riprel_store"):
        return 6  # opcode + reg slot + 4-byte bytecode-relative displacement
    if kind in ("cmpmem", "opmem", "lea", "opmemdst"):
        return 7  # opcode + reg slot + base slot + 4-byte displacement
    if kind in ("cmpriprel", "opriprel", "learip", "opmemdstrip"):
        return 6  # opcode + reg slot + 4-byte bytecode-relative displacement
    if kind in ("leaidx", "opmemidx"):
        return 9  # opcode + reg + base + index slots + scale shift + 4-byte disp
    if kind == "incdec":
        return 2  # opcode + reg slot
    if kind == "movx":
        return 7  # opcode + reg slot + base slot + 4-byte displacement
    if kind == "movxidx":
        return 9  # opcode + reg + base + index slots + scale shift + 4-byte disp
    if kind in ("jmp", "jcc"):
        return 5
    return 1  # nop, exit


def encode_region(region: Region, scheme: RegionScheme, bytecode_base: int) -> bytes:
    """Two-pass lowering: assign offsets, emit, then XOR-encrypt.

    ``bytecode_base`` is the vaddr the bytecode is assembled at; rip-relative
    targets are stored as a signed 32-bit offset from it so the interpreter can
    recompute them from its own bytecode pointer, base-independently.
    """
    offsets: list[int] = []
    cursor = 0
    for item in region.instructions:
        offsets.append(cursor)
        cursor += _item_size(item)

    slot_of = scheme.slot_perm  # logical register index -> shuffled frame slot
    pick = random.Random(scheme.junk_seed).choice  # deterministic per build
    plain = bytearray()

    def emit_opcode(handler_key: str) -> None:
        # Choose one of the handler's interchangeable opcodes, then mask it with
        # its own stream position so the same operation does not encode to the
        # same byte twice and a single-byte XOR of the whole blob no longer
        # exposes the opcode stream. The dispatcher subtracts the position back
        # out before decoding.
        opcode = pick(scheme.dup[handler_key])
        plain.append(opcode ^ (len(plain) & 0xFF))

    for item in region.instructions:
        kind = item[0]
        if kind == "op":
            op = item[1]
            emit_opcode(_required_key(item))
            plain.append(slot_of[op.dst_index])
            if op.is_immediate:
                plain += pack_immediate(op.value, op.width)
            else:
                plain.append(slot_of[op.value])
        elif kind in ("cmp", "test"):
            _, slot, value, is_imm, width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[slot])
            if is_imm:
                plain += pack_immediate(value, width)
            else:
                plain.append(slot_of[value])
        elif kind == "shift":
            _, _mnemonic, slot, count, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[slot])
            plain.append(count)
        elif kind == "imul":
            _, dst, src, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[dst])
            plain.append(slot_of[src])
        elif kind in ("load", "store"):
            _, reg_slot, base_slot, disp, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain.append(slot_of[base_slot])
            plain += struct.pack("<i", disp)
        elif kind in ("riprel_load", "riprel_store"):
            _, reg_slot, target, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain += struct.pack("<i", target - bytecode_base)
        elif kind == "cmpmem":
            _, reg_slot, base_slot, disp, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain.append(slot_of[base_slot])
            plain += struct.pack("<i", disp)
        elif kind == "cmpriprel":
            _, reg_slot, target, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain += struct.pack("<i", target - bytecode_base)
        elif kind == "opmem":
            _, _mnemonic, reg_slot, base_slot, disp, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain.append(slot_of[base_slot])
            plain += struct.pack("<i", disp)
        elif kind == "opriprel":
            _, _mnemonic, reg_slot, target, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain += struct.pack("<i", target - bytecode_base)
        elif kind == "lea":
            _, reg_slot, base_slot, disp = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain.append(slot_of[base_slot])
            plain += struct.pack("<i", disp)
        elif kind == "learip":
            _, reg_slot, target = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain += struct.pack("<i", target - bytecode_base)
        elif kind == "leaidx":
            _, reg_slot, base_slot, index_slot, shift, disp = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain.append(slot_of[base_slot])
            plain.append(slot_of[index_slot])
            plain.append(shift)
            plain += struct.pack("<i", disp)
        elif kind == "opmemidx":
            _, _mnemonic, reg_slot, base_slot, index_slot, shift, disp, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain.append(slot_of[base_slot])
            plain.append(slot_of[index_slot])
            plain.append(shift)
            plain += struct.pack("<i", disp)
        elif kind == "incdec":
            _, _mnemonic, reg_slot, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
        elif kind == "movx":
            _, _ext, _src_size, _dst_width, reg_slot, base_slot, disp = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain.append(slot_of[base_slot])
            plain += struct.pack("<i", disp)
        elif kind == "movxidx":
            _, _ext, _src_size, _dst_width, reg_slot, base_slot, index_slot, shift, disp = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain.append(slot_of[base_slot])
            plain.append(slot_of[index_slot])
            plain.append(shift)
            plain += struct.pack("<i", disp)
        elif kind == "opmemdst":
            _, _mnemonic, reg_slot, base_slot, disp, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain.append(slot_of[base_slot])
            plain += struct.pack("<i", disp)
        elif kind == "opmemdstrip":
            _, _mnemonic, reg_slot, target, _width = item
            emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot])
            plain += struct.pack("<i", target - bytecode_base)
        elif kind == "jmp":
            emit_opcode("jmp")
            plain += struct.pack("<i", offsets[item[1]])
        elif kind == "jcc":
            emit_opcode(_required_key(item))
            plain += struct.pack("<i", offsets[item[2]])
        elif kind == "nop":
            emit_opcode("nop")
        elif kind == "exit":
            emit_opcode(_required_key(item))
    key = scheme.xor_key
    return bytes(byte ^ key for byte in plain)


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
        f"  cmp al, {sum(len(indices) for indices in scheme.dup.values())}\n  jae vm_exit\n"
        # Base-independent indirect dispatch: each table entry is a 32-bit signed
        # offset from vm_table to its handler, so the jump survives rebasing/ASLR
        # exactly like the rel32 jumps the rest of the blob relies on.
        "  lea r14, [rip+vm_table]\n  movsxd rax, dword ptr [r14+rax*4]\n  add rax, r14\n  jmp rax\n"
    )

    reload_seq = "".join(
        f"  mov {name}, qword ptr [rsp+{slot[index] * 8}]\n" for index, name in enumerate(GP_REGISTERS) if name != "rsp"
    )

    # Each opcode index gets its own handler instance (an operation with two
    # indices is emitted twice, each copy carrying different junk), so the
    # opcode->operation map is not one-to-one and the duplicate handlers carry
    # no shared byte signature.
    index_to_key: dict[int, str] = {}
    for handler_key, indices in scheme.dup.items():
        for index in indices:
            index_to_key[index] = handler_key
    total = len(index_to_key)

    junk_rng = random.Random(scheme.junk_seed)
    for index in range(total):
        handler_key = index_to_key[index]
        # Reachable head junk makes duplicate handlers diverge in executed code.
        lines.append(f"H_{index}:\n{_live_junk_asm(junk_rng)}")
        if handler_key.startswith("op_"):
            lines.append(_op_handler_asm(handler_key, key, key_qword, key_dword))
        elif handler_key.startswith(("cmp_", "test_")):
            lines.append(_compare_handler_asm(handler_key, key, key_qword, key_dword))
        elif handler_key.startswith(("shl_", "shr_", "sar_")):
            lines.append(_shift_handler_asm(handler_key, key))
        elif handler_key.startswith("imul_"):
            lines.append(_imul_handler_asm(handler_key, key))
        elif handler_key.startswith(("cmpmem_", "cmpriprel_")):
            lines.append(_cmp_memory_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith(("opmemdst_", "opmemdstrip_")):
            lines.append(_op_memdst_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith(("opmem_", "opriprel_")):
            lines.append(_op_memory_handler_asm(handler_key, key, key_dword))
        elif handler_key in ("lea", "learip"):
            lines.append(_lea_handler_asm(handler_key, key, key_dword))
        elif handler_key == "leaidx":
            lines.append(_lea_indexed_handler_asm(key, key_dword))
        elif handler_key.startswith("opmemidx_"):
            lines.append(_op_mem_indexed_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith("incdec_"):
            lines.append(_incdec_handler_asm(handler_key, key))
        elif handler_key.startswith("movxidx_"):
            lines.append(_movx_indexed_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith("movx_"):
            lines.append(_movx_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith(("riprel_load_", "riprel_store_")):
            lines.append(_riprel_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith(("load_", "store_")):
            lines.append(_memory_handler_asm(handler_key, key, key_dword))
        elif handler_key == "jmp":
            lines.append(retarget)
        elif handler_key.startswith("jcc_"):
            native = handler_key.split("_", 1)[1]
            lines.append(
                f"  push qword ptr [rsp+{_FLAGS_OFFSET}]\n  popfq\n  {native} T_{index}\n"
                "  add rsi, 5\n  jmp vm_dispatch\n"
                f"T_{index}:\n{retarget}"
            )
        elif handler_key == "nop":
            lines.append("  add rsi, 1\n  jmp vm_dispatch\n")
        elif handler_key.startswith("exit_"):
            exit_addr = int(handler_key.split("_", 1)[1])
            lines.append(f"{reload_seq}  add rsp, {_FRAME_SIZE}\n  jmp {hex(exit_addr)}\n")
        # Junk after the handler's terminating jump - unreachable, never runs.
        lines.append(_junk_asm(junk_rng))

    # Every index in 0..total-1 maps to a handler; the bounds guard above sends an
    # out-of-range (corrupt) opcode to the default exit so it cannot leave the VM.
    table = "".join(f"  .long H_{index} - vm_table\n" for index in range(total))
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
    # The bytecode is appended right after the interpreter, so its base is the
    # cave plus the interpreter's assembled length; rip-relative targets are
    # encoded relative to it. A target too far to express as a signed 32-bit
    # offset leaves the function native.
    bytecode_base = cave_vaddr + len(encoding)
    try:
        bytecode = encode_region(region, scheme, bytecode_base)
    except struct.error:
        logger.debug("rip-relative target out of 32-bit range; leaving function native")
        return None
    return bytes(encoding) + bytecode
