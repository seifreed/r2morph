"""Interpreter-assembly and bytecode generation for region virtualization.

Given a lowered :class:`Region` and its per-instance :class:`RegionScheme`,
this module emits the VM: :func:`encode_region` lowers the item list to the
encrypted, position-masked bytecode, :func:`_interpreter_asm` generates the
dispatch loop and the per-handler instances, and :func:`build_region_blob`
assembles the interpreter at its cave vaddr, XOR-encrypts the dispatch table on
the assembled bytes, and appends the bytecode.

The lifting side that produces the :class:`Region` lives in
:mod:`code_virtualization_region`; both share the value objects in
:mod:`code_virtualization_region_models`.
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
    pack_immediate,
)
from r2morph.mutations.code_virtualization_region_handlers import (
    _FLAGS_OFFSET,
    _FRAME_SIZE,
    _GUARD,
    _cmp_memory_handler_asm,
    _compare_handler_asm,
    _imul3_handler_asm,
    _imul_handler_asm,
    _incdec_handler_asm,
    _lea_handler_asm,
    _lea_indexed_handler_asm,
    _lea_indexed_nobase_handler_asm,
    _leave_handler_asm,
    _memory_handler_asm,
    _mov_from_rsp_handler_asm,
    _mov_to_rsp_handler_asm,
    _movx_handler_asm,
    _movx_indexed_handler_asm,
    _op_handler_asm,
    _op_mba_handler_asm,
    _op_mem_indexed_handler_asm,
    _op_memdst_handler_asm,
    _op_memory_handler_asm,
    _pop_handler_asm,
    _push_handler_asm,
    _pushi_handler_asm,
    _riprel_handler_asm,
    _rspadj_handler_asm,
    _shift_handler_asm,
)
from r2morph.mutations.code_virtualization_region_integrity import (
    _CHECKSUM_OFFSET,
    checksum_prologue_asm,
    compute_build_checksum,
)
from r2morph.mutations.code_virtualization_region_models import (
    _DWORD_BROADCAST,
    _QWORD_BROADCAST,
    Region,
    RegionScheme,
    _required_key,
)

logger = logging.getLogger(__name__)


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
    if kind in ("op", "opmba"):
        op: VirtualizedOp = item[1]
        if op.is_immediate:
            return 2 + (8 if op.width == 64 else 4)
        return 3
    if kind in ("cmp", "test"):
        return 2 + (8 if item[4] == 64 else 4) if item[3] else 3
    if kind in ("shift", "imul"):
        return 3
    if kind == "imul3":
        return 7  # opcode + dst slot + src slot + 4-byte immediate
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
    if kind == "leaidxnb":
        return 8  # opcode + reg + index slot + scale shift + 4-byte disp (no base)
    if kind in ("push", "pop"):
        return 2  # opcode + reg slot
    if kind == "pushi":
        return 9  # opcode + 8-byte immediate
    if kind == "rspadj":
        return 5  # opcode + 4-byte immediate
    if kind == "movfromrsp":
        return 2  # opcode + dst slot
    if kind in ("movtorsp", "leave"):
        return 2  # opcode + reg slot
    if kind == "incdec":
        return 2  # opcode + reg slot
    if kind == "movx":
        return 7  # opcode + reg slot + base slot + 4-byte displacement
    if kind == "movxidx":
        return 9  # opcode + reg + base + index slots + scale shift + 4-byte disp
    if kind in ("jmp", "jcc"):
        return 5
    return 1  # nop, exit, enter_inner, inner_exit (opcode byte only)


def encode_region(region: Region, scheme: RegionScheme, bytecode_base: int, checksum: int = 0) -> bytes:
    """Two-pass lowering: assign offsets, emit, then XOR-encrypt.

    ``bytecode_base`` is the vaddr the bytecode is assembled at; rip-relative
    targets are stored as a signed 32-bit offset from it so the interpreter can
    recompute them from its own bytecode pointer, base-independently.

    ``checksum`` is the expected runtime self-checksum of the interpreter; it is
    XORed into every opcode byte so the dispatch (which re-derives it at runtime)
    cancels it on a faithful build and misdecodes if the interpreter is patched.
    """
    offsets: list[int] = []
    cursor = 0
    for item in region.instructions:
        offsets.append(cursor)
        cursor += _item_size(item)

    slot_of = scheme.slot_perm  # logical register index -> shuffled frame slot
    pick = random.Random(scheme.junk_seed).choice  # deterministic per build
    plain = bytearray()

    def emit_opcode(handler_key: str) -> int:
        # Choose one of the handler's interchangeable opcodes, then mask it with
        # its own stream position so the same operation does not encode to the
        # same byte twice and a single-byte XOR of the whole blob no longer
        # exposes the opcode stream. The dispatcher subtracts the position back
        # out before decoding. The position is returned so this item's operands
        # are masked with it too (the handler un-masks them with r13b, which the
        # dispatch left holding the position), keying the operand decrypt by
        # ``key XOR position`` so no single handler reveals a reusable key.
        position = len(plain) & 0xFF
        opcode = pick(scheme.dup[handler_key])
        plain.append(opcode ^ position ^ checksum)
        return position

    def emit_imm(value: int, width: int, position: int) -> None:
        plain.extend(byte ^ position for byte in pack_immediate(value, width))

    def emit_disp(value: int, position: int) -> None:
        plain.extend(byte ^ position for byte in struct.pack("<i", value))

    for item in region.instructions:
        kind = item[0]
        # Every operand is masked with the opcode's stream position (returned by
        # emit_opcode); the handler un-masks each with r13b, so no operand is
        # decrypted by a lone constant key. emit_imm/emit_disp fold the position
        # into each byte of a multi-byte immediate or displacement.
        if kind in ("op", "opmba"):
            op = item[1]
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[op.dst_index] ^ p)
            if op.is_immediate:
                emit_imm(op.value, op.width, p)
            else:
                plain.append(slot_of[op.value] ^ p)
        elif kind in ("cmp", "test"):
            _, slot, value, is_imm, width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[slot] ^ p)
            if is_imm:
                emit_imm(value, width, p)
            else:
                plain.append(slot_of[value] ^ p)
        elif kind == "shift":
            _, _mnemonic, slot, count, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[slot] ^ p)
            plain.append(count ^ p)
        elif kind == "imul":
            _, dst, src, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[dst] ^ p)
            plain.append(slot_of[src] ^ p)
        elif kind == "imul3":
            _, dst, src, imm, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[dst] ^ p)
            plain.append(slot_of[src] ^ p)
            emit_imm(imm, 32, p)
        elif kind in ("push", "pop"):
            _, reg_slot, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
        elif kind == "pushi":
            _, value, _width = item
            p = emit_opcode(_required_key(item))
            emit_imm(value, 64, p)
        elif kind == "rspadj":
            _, _mnemonic, value = item
            p = emit_opcode(_required_key(item))
            emit_imm(value, 32, p)
        elif kind in ("movfromrsp", "movtorsp", "leave"):
            _, reg_slot = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
        elif kind in ("load", "store"):
            _, reg_slot, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            plain.append(slot_of[base_slot] ^ p)
            emit_disp(disp, p)
        elif kind in ("riprel_load", "riprel_store"):
            _, reg_slot, target, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            emit_disp(target - bytecode_base, p)
        elif kind == "cmpmem":
            _, reg_slot, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            plain.append(slot_of[base_slot] ^ p)
            emit_disp(disp, p)
        elif kind == "cmpriprel":
            _, reg_slot, target, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            emit_disp(target - bytecode_base, p)
        elif kind == "opmem":
            _, _mnemonic, reg_slot, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            plain.append(slot_of[base_slot] ^ p)
            emit_disp(disp, p)
        elif kind == "opriprel":
            _, _mnemonic, reg_slot, target, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            emit_disp(target - bytecode_base, p)
        elif kind == "lea":
            _, reg_slot, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            plain.append(slot_of[base_slot] ^ p)
            emit_disp(disp, p)
        elif kind == "learip":
            _, reg_slot, target, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            emit_disp(target - bytecode_base, p)
        elif kind == "leaidx":
            _, reg_slot, base_slot, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            plain.append(slot_of[base_slot] ^ p)
            plain.append(slot_of[index_slot] ^ p)
            plain.append(shift ^ p)
            emit_disp(disp, p)
        elif kind == "leaidxnb":
            _, reg_slot, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            plain.append(slot_of[index_slot] ^ p)
            plain.append(shift ^ p)
            emit_disp(disp, p)
        elif kind == "opmemidx":
            _, _mnemonic, reg_slot, base_slot, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            plain.append(slot_of[base_slot] ^ p)
            plain.append(slot_of[index_slot] ^ p)
            plain.append(shift ^ p)
            emit_disp(disp, p)
        elif kind == "incdec":
            _, _mnemonic, reg_slot, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
        elif kind == "movx":
            _, _ext, _src_size, _dst_width, reg_slot, base_slot, disp = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            plain.append(slot_of[base_slot] ^ p)
            emit_disp(disp, p)
        elif kind == "movxidx":
            _, _ext, _src_size, _dst_width, reg_slot, base_slot, index_slot, shift, disp = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            plain.append(slot_of[base_slot] ^ p)
            plain.append(slot_of[index_slot] ^ p)
            plain.append(shift ^ p)
            emit_disp(disp, p)
        elif kind == "opmemdst":
            _, _mnemonic, reg_slot, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            plain.append(slot_of[base_slot] ^ p)
            emit_disp(disp, p)
        elif kind == "opmemdstrip":
            _, _mnemonic, reg_slot, target, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
            emit_disp(target - bytecode_base, p)
        elif kind == "jmp":
            p = emit_opcode("jmp")
            emit_disp(offsets[item[1]], p)
        elif kind == "jcc":
            p = emit_opcode(_required_key(item))
            emit_disp(offsets[item[2]], p)
        elif kind == "nop":
            emit_opcode("nop")
        elif kind in ("exit", "enter_inner", "inner_exit"):
            emit_opcode(_required_key(item))
    key = scheme.xor_key
    return bytes(byte ^ key for byte in plain)


def handler_instances_asm(
    index_to_key: dict[int, str],
    *,
    key: int,
    key_qword: str,
    key_dword: str,
    rsp_off: int,
    junk_rng: random.Random,
    reload_seq: str,
    retarget: str,
    frame_size: int,
    extra: dict[str, str] | None = None,
) -> str:
    """Emit the ``H_{index}`` handler instances for one interpreter (or layer).

    ``index_to_key`` maps each global handler index to its handler key; ``extra``
    supplies bodies for handler keys outside the standard dispatch table (e.g.
    the nested-VM transfer handlers). All bodies jump back to the shared
    ``vm_dispatch`` and carry per-instance reachable/unreachable junk.
    """
    extra = extra or {}
    lines: list[str] = []
    for index in sorted(index_to_key):
        handler_key = index_to_key[index]
        # Reachable head junk makes duplicate handlers diverge in executed code.
        lines.append(f"H_{index}:\n{_live_junk_asm(junk_rng)}")
        if handler_key in extra:
            lines.append(extra[handler_key])
        elif handler_key.startswith("opmba_"):
            lines.append(_op_mba_handler_asm(handler_key, key, key_qword, key_dword))
        elif handler_key.startswith("op_"):
            lines.append(_op_handler_asm(handler_key, key, key_qword, key_dword))
        elif handler_key.startswith(("cmp_", "test_")):
            lines.append(_compare_handler_asm(handler_key, key, key_qword, key_dword))
        elif handler_key.startswith(("shl_", "shr_", "sar_")):
            lines.append(_shift_handler_asm(handler_key, key))
        elif handler_key.startswith("imul3_"):
            lines.append(_imul3_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith("push_"):
            lines.append(_push_handler_asm(key, rsp_off))
        elif handler_key.startswith("pop_"):
            lines.append(_pop_handler_asm(key, rsp_off))
        elif handler_key == "pushi":
            lines.append(_pushi_handler_asm(key_qword, rsp_off))
        elif handler_key.startswith("rspadj_"):
            lines.append(_rspadj_handler_asm(handler_key, key_dword, rsp_off))
        elif handler_key == "movfromrsp":
            lines.append(_mov_from_rsp_handler_asm(key, rsp_off))
        elif handler_key == "movtorsp":
            lines.append(_mov_to_rsp_handler_asm(key, rsp_off))
        elif handler_key == "leave":
            lines.append(_leave_handler_asm(key, rsp_off))
        elif handler_key.startswith("imul_"):
            lines.append(_imul_handler_asm(handler_key, key))
        elif handler_key.startswith(("cmpmem_", "cmpriprel_")):
            lines.append(_cmp_memory_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith(("opmemdst_", "opmemdstrip_")):
            lines.append(_op_memdst_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith(("opmem_", "opriprel_")):
            lines.append(_op_memory_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith("leaidxnb_"):
            lines.append(_lea_indexed_nobase_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith("leaidx_"):
            lines.append(_lea_indexed_handler_asm(handler_key, key, key_dword))
        elif handler_key.startswith(("lea_", "learip_")):
            lines.append(_lea_handler_asm(handler_key, key, key_dword))
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
            lines.append(f"{reload_seq}  add rsp, {frame_size}\n  jmp {hex(exit_addr)}\n")
        # Junk after the handler's terminating jump - unreachable, never runs.
        lines.append(_junk_asm(junk_rng))
    return "".join(lines)


def _interpreter_asm(region: Region, scheme: RegionScheme) -> str:
    key = scheme.xor_key
    key_qword = hex((key * _QWORD_BROADCAST) & 0xFFFFFFFFFFFFFFFF)
    key_dword = hex((key * _DWORD_BROADCAST) & 0xFFFFFFFF)
    retarget = (
        f"  mov eax, dword ptr [rsi+1]\n  xor eax, {key_dword}\n"
        # Un-mask the position the encoder folded into the target (r13b holds it
        # from the dispatch), broadcast to 32 bits - the branch offset is keyed by
        # key XOR position like every other operand.
        f"  movzx r10d, r13b\n  imul r10d, r10d, {hex(_DWORD_BROADCAST)}\n  xor eax, r10d\n"
        "  lea r9, [rip+bytecode]\n  add r9, rax\n  mov rsi, r9\n  jmp vm_dispatch\n"
    )

    slot = scheme.slot_perm  # logical register index -> shuffled frame slot
    rsp_off = slot[RSP_INDEX] * 8  # byte offset of the relocated program rsp slot
    lines = [f"vm_entry:\n  sub rsp, {_FRAME_SIZE}\n"]
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov qword ptr [rsp+{slot[index] * 8}], {name}\n")
    # Anti-tamper: checksum the interpreter's own code into a frame slot the
    # dispatch folds into every opcode decrypt. Runs after the spill, so the
    # scratch registers it clobbers are already saved.
    lines.append(checksum_prologue_asm(scheme.xor_key))
    lines.append(
        # Capture the program's entry rsp, then relocate its virtual stack a
        # guard distance below the VM frame so the function's own push/pop never
        # collides with the spilled context. rsp is only ever a memory base or a
        # push/pop target, so this constant shift stays self-consistent.
        f"  lea rax, [rsp+{_FRAME_SIZE}]\n  sub rax, {_GUARD}\n  mov qword ptr [rsp+{slot[RSP_INDEX] * 8}], rax\n"
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
        # Fold in the position mask (r13b) and the runtime self-checksum: the
        # encoder pre-biased the opcode with the expected checksum, so a faithful
        # interpreter cancels it and a tampered one misdecodes every opcode.
        f"  xor al, {key}\n  xor al, r13b\n  xor al, byte ptr [rsp+{_CHECKSUM_OFFSET}]\n"
        f"  cmp al, {sum(len(indices) for indices in scheme.dup.values())}\n  jae vm_exit\n"
        # Base-independent indirect dispatch: each table entry is a 32-bit signed
        # offset from vm_table to its handler, so the jump survives rebasing/ASLR
        # exactly like the rel32 jumps the rest of the blob relies on. The stored
        # offsets are XOR-encrypted, so the table is not a plaintext handler map a
        # disassembler can recover as a switch; the dispatch decrypts each entry.
        # The table key is itself diffused with the runtime self-checksum
        # (broadcast to 32 bits), so tampering corrupts handler-address resolution
        # too, not just the opcode decode - the build pre-folds the same value.
        f"  lea r14, [rip+vm_table]\n  mov eax, dword ptr [r14+rax*4]\n  xor eax, {hex(scheme.table_key)}\n"
        f"  movzx ecx, byte ptr [rsp+{_CHECKSUM_OFFSET}]\n  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n"
        "  movsxd rax, eax\n  add rax, r14\n  jmp rax\n"
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
    lines.append(
        handler_instances_asm(
            index_to_key,
            key=key,
            key_qword=key_qword,
            key_dword=key_dword,
            rsp_off=rsp_off,
            junk_rng=junk_rng,
            reload_seq=reload_seq,
            retarget=retarget,
            frame_size=_FRAME_SIZE,
        )
    )

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
    # The dispatch table (``total`` 32-bit offsets) is the tail of the assembled
    # interpreter; XOR-encrypt each entry in place so the handler addresses are
    # not a plaintext jump table. The dispatch decrypts them at runtime with the
    # same key, and keystone cannot XOR a label difference it computes itself, so
    # the encryption happens here on the assembled bytes.
    data = bytearray(encoding)
    total = sum(len(indices) for indices in scheme.dup.values())
    table_start = len(data) - total * 4
    # Expected runtime self-checksum over the interpreter code (everything up to
    # the dispatch table, so the table encryption below does not perturb it); the
    # encoder folds it into the opcodes, and the table key is diffused with it too.
    checksum = compute_build_checksum(bytes(data[:table_start]), scheme.xor_key)
    table_key = scheme.table_key ^ (checksum * 0x01010101)
    for entry_index in range(total):
        offset = table_start + entry_index * 4
        encrypted = int.from_bytes(data[offset : offset + 4], "little") ^ table_key
        data[offset : offset + 4] = encrypted.to_bytes(4, "little")
    # The bytecode is appended right after the interpreter, so its base is the
    # cave plus the interpreter's assembled length; rip-relative targets are
    # encoded relative to it. A target too far to express as a signed 32-bit
    # offset leaves the function native.
    bytecode_base = cave_vaddr + len(data)
    try:
        bytecode = encode_region(region, scheme, bytecode_base, checksum)
    except struct.error:
        logger.debug("rip-relative target out of 32-bit range; leaving function native")
        return None
    return bytes(data) + bytecode
