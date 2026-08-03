"""Bytecode encoding for region virtualization.

Split out of :mod:`code_virtualization_region_codegen` to keep that aggregator
within the file-size budget. :func:`encode_region` performs the two-pass lowering
of a lowered :class:`Region`'s item list to encrypted, position-masked bytecode;
:func:`_item_size` gives each item's encoded byte length (used to assign offsets).
Both are re-exported from :mod:`code_virtualization_region_codegen` so existing
imports keep working.
"""

from __future__ import annotations

import random
import struct
from typing import Any

from r2morph.mutations.code_virtualization_engine import VirtualizedOp, pack_immediate
from r2morph.mutations.code_virtualization_layout import (
    idx_permuted_fields,
    imul3_permuted_fields,
    mem_permuted_fields,
    op_permuted_fields,
    pair_permuted_fields,
    permuted_fields,
    shift_permuted_fields,
)
from r2morph.mutations.code_virtualization_region_models import Region, RegionScheme, _required_key


def _item_size(item: tuple[Any, ...]) -> int:
    kind = item[0]
    if kind in ("vpush", "vpop"):
        return 2  # opcode + slot byte
    if kind == "vpushi":
        return 1 + (8 if item[2] == 64 else 4)  # opcode + width-sized immediate
    if kind in ("vbinop", "vbinopsynth", "vcmpsynth"):
        return 1  # opcode only (operands come off the vstack)
    if kind in ("fsave", "frestore"):
        return 1  # opcode only (virtual RFLAGS save/restore through the vstack)
    if kind in ("vload", "vstore"):
        return 7  # opcode + (unused) reg slot + base slot + 4-byte displacement
    if kind in ("vloadidx", "vstoreidx"):
        return 9  # opcode + (unused) reg + base + index slots + scale shift + 4-byte disp
    if kind in ("vloadrip", "vstorerip"):
        return 6  # opcode + (unused) reg slot + 4-byte bytecode-relative displacement
    if kind == "vlea":
        return 7  # opcode + (unused) reg slot + base slot + 4-byte displacement
    if kind == "vlearip":
        return 6  # opcode + (unused) reg slot + 4-byte bytecode-relative displacement
    if kind == "vleaidx":
        return 9  # opcode + (unused) reg + base + index slots + scale shift + 4-byte disp
    if kind == "vleaidxnb":
        return 8  # opcode + (unused) reg + index slot + scale shift + 4-byte disp (no base)
    if kind == "vmovx":
        return 7  # opcode + (unused) reg slot + base slot + 4-byte displacement
    if kind == "vmovxidx":
        return 9  # opcode + (unused) reg + base + index slots + scale shift + 4-byte disp
    if kind == "vshift":
        return 2  # opcode + count byte
    if kind in ("op", "opmba", "opsynth"):
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
    if kind in ("load", "store", "fpload", "fpstore"):
        return 7  # opcode + reg/xmm slot + base slot + 4-byte displacement
    if kind in ("fploadrip", "fpstorerip"):
        return 6  # opcode + xmm index + 4-byte bytecode-relative displacement
    if kind in ("fploadidx", "fpstoreidx"):
        return 9  # opcode + xmm index + base + index slots + scale shift + 4-byte disp
    if kind in ("fploadidxnb", "fpstoreidxnb"):
        return 8  # opcode + xmm index + index slot + scale shift + 4-byte disp (no base)
    if kind == "fparith":
        return 3  # opcode + dst xmm index + src xmm index
    if kind in ("cvti2f", "cvtf2i"):
        return 3  # opcode + xmm index + GP slot (order depends on direction)
    if kind == "fpcmp":
        return 3  # opcode + left xmm index + right xmm index
    if kind == "fpmov":
        return 3  # opcode + dst xmm index + src xmm index
    if kind == "fppacked":
        return 3  # opcode + dst xmm index + src xmm index
    if kind in ("fppload", "fppstore", "fppackedmem"):
        return 7  # opcode + xmm index + base slot + 4-byte displacement
    if kind in ("fpploadrip", "fppstorerip", "fppackedmemrip"):
        return 6  # opcode + xmm index + 4-byte bytecode-relative displacement
    if kind in ("fpploadidx", "fppstoreidx", "fppackedmemidx"):
        return 9  # opcode + xmm index + base + index slots + scale shift + 4-byte disp
    if kind == "fparithmem":
        return 7  # opcode + dst xmm index + base slot + 4-byte displacement
    if kind == "fparithmemrip":
        return 6  # opcode + dst xmm index + 4-byte bytecode-relative displacement
    if kind == "fparithmemidx":
        return 9  # opcode + dst xmm index + base + index slots + scale shift + 4-byte disp
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
    if kind == "setcc":
        return 2  # opcode + destination slot byte
    if kind == "cmov":
        return 3  # opcode + destination slot + source slot
    if kind == "call":
        return 5  # opcode + 4-byte bytecode-relative target offset
    if kind == "icall":
        return 2  # opcode + register slot holding the runtime target
    if kind == "ijmp":
        return 2  # opcode + register slot holding the runtime jump target
    if kind == "callmem":
        return 7  # opcode + (unused) reg slot + base slot + 4-byte displacement
    if kind == "callmemrip":
        return 6  # opcode + (unused) reg slot + 4-byte bytecode-relative offset
    if kind == "callmemidx":
        return 9  # opcode + (unused) reg + base + index slots + scale shift + disp
    return 1  # nop, exit, enter_inner, inner_exit (opcode byte only)


def build_ijmp_targets(region: Region) -> list[tuple[int, int]]:
    """Native-address -> bytecode-offset pairs a computed jump may resolve to.

    Mirrors :func:`encode_region`'s offset assignment so a runtime target address
    can be translated to the bytecode offset of its virtualized item, letting an
    ``ijmp`` re-enter the VM at the virtualized copy of its target rather than the
    overwritten native code. Empty unless the dispatch-region contract populated
    ``region.target_map``, so an ordinary region emits no map.
    """
    if not region.target_map:
        return []
    offsets: list[int] = []
    cursor = 0
    for item in region.instructions:
        offsets.append(cursor)
        cursor += _item_size(item)
    pairs: list[tuple[int, int]] = []
    for addr, item_index in sorted(region.target_map.items()):
        if 0 <= item_index < len(offsets):
            pairs.append((addr, offsets[item_index]))
    return pairs


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

    def emit_pair(position: int, first: int, second: int) -> None:
        # Emit two single-byte operands (FP register handlers) in this build's
        # order; the handler reads them at the matching offsets via pair_offsets.
        # The permutation is name-independent, so generic field names suffice.
        values = {"a": first, "b": second}
        for name, _size in pair_permuted_fields("a", "b", scheme.field_perm):
            plain.append(values[name] ^ position)

    def emit_mem(position: int, reg_slot: int, base_slot: int | None, disp: int) -> None:
        # Emit a memory item's operand fields (register slot, optional base slot,
        # 4-byte displacement) in this build's permuted order; the handler reads
        # them at the matching offsets via mem_offsets, so the two always agree.
        # base_slot is None for the rip-relative form (no base byte).
        riprel = base_slot is None
        field_bytes = {"reg": bytes([reg_slot]), "disp": struct.pack("<i", disp)}
        if base_slot is not None:
            field_bytes["base"] = bytes([base_slot])
        for name, _size in mem_permuted_fields(riprel, scheme.field_perm):
            plain.extend(byte ^ position for byte in field_bytes[name])

    def emit_idx(position: int, reg_slot: int, base_slot: int | None, index_slot: int, shift: int, disp: int) -> None:
        # Emit a scaled-index item's operand fields (register, optional base,
        # index, scale shift, 4-byte displacement) in this build's permuted order;
        # the handler reads them at the matching offsets via idx_offsets.
        nobase = base_slot is None
        field_bytes = {
            "reg": bytes([reg_slot]),
            "index": bytes([index_slot]),
            "shift": bytes([shift]),
            "disp": struct.pack("<i", disp),
        }
        if base_slot is not None:
            field_bytes["base"] = bytes([base_slot])
        for name, _size in idx_permuted_fields(nobase, scheme.field_perm):
            plain.extend(byte ^ position for byte in field_bytes[name])

    for item in region.instructions:
        kind = item[0]
        # Every operand is masked with the opcode's stream position (returned by
        # emit_opcode); the handler un-masks each with r13b, so no operand is
        # decrypted by a lone constant key. emit_imm/emit_disp fold the position
        # into each byte of a multi-byte immediate or displacement.
        if kind in ("op", "opmba", "opsynth"):
            op = item[1]
            handler_key = _required_key(item)
            p = emit_opcode(handler_key)
            # Emit the operand fields in this build's permuted order; the handler
            # derives the same offsets from scheme.field_perm, so they agree.
            field_bytes = {"dst": bytes([slot_of[op.dst_index]])}
            if op.is_immediate:
                field_bytes["imm"] = pack_immediate(op.value, op.width)
            else:
                field_bytes["src"] = bytes([slot_of[op.value]])
            for name, _size in permuted_fields(handler_key, scheme.field_perm):
                plain.extend(byte ^ p for byte in field_bytes[name])
        elif kind in ("vpush", "vpop"):
            # A micro-op push/pop carries one slot operand (no permutation needed).
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[item[1]] ^ p)
        elif kind == "vpushi":
            # Push a width-sized immediate, masked byte-wise by the opcode position.
            _, value, width = item
            p = emit_opcode(_required_key(item))
            plain.extend(byte ^ p for byte in pack_immediate(value, width))
        elif kind == "vshift":
            # Shift the top vstack cell by a one-byte count (no permutation needed).
            p = emit_opcode(_required_key(item))
            plain.append(item[2] ^ p)
        elif kind in ("vbinop", "vbinopsynth", "vcmpsynth"):
            # The fold/compare takes its operands off the vstack: opcode only.
            emit_opcode(_required_key(item))
        elif kind in ("vload", "vstore"):
            # Reuse the load operand layout (reg/base/disp); the value moves through
            # the vstack, so the register field is an unused placeholder.
            _, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[0], slot_of[base_slot], disp)
        elif kind in ("vloadidx", "vstoreidx"):
            # Reuse the scaled-index operand layout; the register field is unused
            # (the value moves through the vstack).
            _, base_slot, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, slot_of[0], slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind in ("vloadrip", "vstorerip"):
            # Reuse the rip-relative operand layout (reg/offset); the register field
            # is an unused placeholder. The target is stored as a signed offset from
            # the bytecode base, recomputed against r15 at runtime.
            _, target, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[0], None, target - bytecode_base)
        elif kind == "vlea":
            # Reuse the base+disp operand layout; the register field is an unused
            # placeholder (the computed address goes on the vstack, not a register).
            _, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[0], slot_of[base_slot], disp)
        elif kind == "vlearip":
            # Reuse the rip-relative operand layout; the register field is unused. The
            # target is stored as a signed offset from the bytecode base (r15).
            _, target, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[0], None, target - bytecode_base)
        elif kind == "vleaidx":
            # Reuse the scaled-index operand layout; the register field is unused.
            _, base_slot, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, slot_of[0], slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind == "vleaidxnb":
            # Reuse the no-base scaled-index operand layout (base None); reg unused.
            _, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, slot_of[0], None, slot_of[index_slot], shift, disp)
        elif kind == "vmovx":
            # Reuse the base+disp operand layout; the register field is an unused
            # placeholder (the extended value goes on the vstack, not a register).
            _, _ext, _src_size, _dst_width, base_slot, disp = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[0], slot_of[base_slot], disp)
        elif kind == "vmovxidx":
            # Reuse the scaled-index operand layout; the register field is unused.
            _, _ext, _src_size, _dst_width, base_slot, index_slot, shift, disp = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, slot_of[0], slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind in ("cmp", "test"):
            _, slot, value, is_imm, width = item
            p = emit_opcode(_required_key(item))
            if is_imm:
                field_bytes = {"dst": bytes([slot_of[slot]]), "imm": pack_immediate(value, width)}
            else:
                field_bytes = {"dst": bytes([slot_of[slot]]), "src": bytes([slot_of[value]])}
            for name, _size in op_permuted_fields(is_imm, width, scheme.field_perm):
                plain.extend(byte ^ p for byte in field_bytes[name])
        elif kind == "shift":
            _, _mnemonic, slot, count, _width = item
            p = emit_opcode(_required_key(item))
            field_bytes = {"slot": bytes([slot_of[slot]]), "count": bytes([count])}
            for name, _size in shift_permuted_fields(scheme.field_perm):
                plain.extend(byte ^ p for byte in field_bytes[name])
        elif kind == "imul":
            _, dst, src, width = item
            p = emit_opcode(_required_key(item))
            field_bytes = {"dst": bytes([slot_of[dst]]), "src": bytes([slot_of[src]])}
            for name, _size in op_permuted_fields(False, width, scheme.field_perm):
                plain.extend(byte ^ p for byte in field_bytes[name])
        elif kind == "imul3":
            _, dst, src, imm, _width = item
            p = emit_opcode(_required_key(item))
            field_bytes = {"dst": bytes([slot_of[dst]]), "src": bytes([slot_of[src]]), "imm": pack_immediate(imm, 32)}
            for name, _size in imul3_permuted_fields(scheme.field_perm):
                plain.extend(byte ^ p for byte in field_bytes[name])
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
            emit_mem(p, slot_of[reg_slot], slot_of[base_slot], disp)
        elif kind in ("fpload", "fpstore"):
            # The reg field carries the XMM index verbatim (XMM slots are direct
            # index*16, not part of the GP slot_perm); the base is a GP slot.
            _, xmm_index, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, xmm_index, slot_of[base_slot], disp)
        elif kind in ("fploadrip", "fpstorerip"):
            # Rip-relative FP memory: the target is re-expressed as a signed offset
            # from the bytecode base (no base slot byte), like GP riprel.
            _, xmm_index, target, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, xmm_index, None, target - bytecode_base)
        elif kind in ("fploadidx", "fpstoreidx"):
            # Scaled-index FP memory: the reg field is the XMM index (raw); base and
            # index are GP slots (slot_perm).
            _, xmm_index, base_slot, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, xmm_index, slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind in ("fploadidxnb", "fpstoreidxnb"):
            # No-base scaled-index FP memory: XMM index (raw) + index GP slot, no
            # base byte (base_slot None selects the no-base operand layout).
            _, xmm_index, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, xmm_index, None, slot_of[index_slot], shift, disp)
        elif kind == "fparith":
            # Two raw XMM indices (no slot_perm), in this build's order.
            _, _op, dst_index, src_index, _width = item
            p = emit_opcode(_required_key(item))
            emit_pair(p, dst_index, src_index)
        elif kind == "cvti2f":
            # int->float: XMM index (raw) + GP source slot (slot_perm), in order.
            _, _fpw, _gpw, xmm_index, gp_slot = item
            p = emit_opcode(_required_key(item))
            emit_pair(p, xmm_index, slot_of[gp_slot])
        elif kind == "cvtf2i":
            # float->int: XMM index (raw) + GP destination slot (slot_perm), in order.
            _, _fpw, _gpw, gp_slot, xmm_index = item
            p = emit_opcode(_required_key(item))
            emit_pair(p, xmm_index, slot_of[gp_slot])
        elif kind in ("fpcmp", "fpmov", "fppacked"):
            # Two raw XMM indices (no slot_perm), in this build's order.
            _, _mode, left_index, right_index = item
            p = emit_opcode(_required_key(item))
            emit_pair(p, left_index, right_index)
        elif kind in ("fppload", "fppstore"):
            # Packed 128-bit load/store: XMM index (raw) + GP base slot (slot_perm).
            _, xmm_index, base_slot, disp = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, xmm_index, slot_of[base_slot], disp)
        elif kind == "fppackedmem":
            # Packed memory-source arith: destination XMM index (raw) + GP base slot.
            _, _mnemonic, xmm_index, base_slot, disp = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, xmm_index, slot_of[base_slot], disp)
        elif kind in ("fpploadrip", "fppstorerip"):
            # Rip-relative packed 128-bit move: XMM index (raw), no base slot, the
            # target as a signed offset from the bytecode base.
            _, xmm_index, target = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, xmm_index, None, target - bytecode_base)
        elif kind == "fppackedmemrip":
            # Rip-relative packed arith: destination XMM index (raw), no base slot.
            _, _mnemonic, xmm_index, target = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, xmm_index, None, target - bytecode_base)
        elif kind in ("fpploadidx", "fppstoreidx"):
            # Scaled-index packed 128-bit move: XMM index (raw); base and index are
            # GP slots (slot_perm).
            _, xmm_index, base_slot, index_slot, shift, disp = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, xmm_index, slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind == "fppackedmemidx":
            # Scaled-index packed arith: destination XMM index (raw); base and index
            # are GP slots (slot_perm).
            _, _mnemonic, xmm_index, base_slot, index_slot, shift, disp = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, xmm_index, slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind == "fparithmem":
            # Memory-source FP arith reuses the mem operand layout: the "reg" field
            # is the destination XMM index (raw), the base is a GP slot.
            _, _op, xmm_index, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, xmm_index, slot_of[base_slot], disp)
        elif kind == "fparithmemrip":
            # Rip-relative FP arith: destination XMM index (raw), no base slot, the
            # target as a signed offset from the bytecode base.
            _, _op, xmm_index, target, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, xmm_index, None, target - bytecode_base)
        elif kind == "fparithmemidx":
            # Scaled-index FP arith: destination XMM index (raw); base and index are
            # GP slots (slot_perm).
            _, _op, xmm_index, base_slot, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, xmm_index, slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind in ("riprel_load", "riprel_store"):
            _, reg_slot, target, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[reg_slot], None, target - bytecode_base)
        elif kind == "cmpmem":
            _, reg_slot, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[reg_slot], slot_of[base_slot], disp)
        elif kind == "cmpriprel":
            _, reg_slot, target, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[reg_slot], None, target - bytecode_base)
        elif kind == "opmem":
            _, _mnemonic, reg_slot, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[reg_slot], slot_of[base_slot], disp)
        elif kind == "opriprel":
            _, _mnemonic, reg_slot, target, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[reg_slot], None, target - bytecode_base)
        elif kind == "lea":
            _, reg_slot, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[reg_slot], slot_of[base_slot], disp)
        elif kind == "learip":
            _, reg_slot, target, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[reg_slot], None, target - bytecode_base)
        elif kind == "leaidx":
            _, reg_slot, base_slot, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, slot_of[reg_slot], slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind == "leaidxnb":
            _, reg_slot, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, slot_of[reg_slot], None, slot_of[index_slot], shift, disp)
        elif kind == "opmemidx":
            _, _mnemonic, reg_slot, base_slot, index_slot, shift, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, slot_of[reg_slot], slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind == "incdec":
            _, _mnemonic, reg_slot, _width = item
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[reg_slot] ^ p)
        elif kind == "movx":
            _, _ext, _src_size, _dst_width, reg_slot, base_slot, disp = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[reg_slot], slot_of[base_slot], disp)
        elif kind == "movxidx":
            _, _ext, _src_size, _dst_width, reg_slot, base_slot, index_slot, shift, disp = item
            p = emit_opcode(_required_key(item))
            emit_idx(p, slot_of[reg_slot], slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind == "opmemdst":
            _, _mnemonic, reg_slot, base_slot, disp, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[reg_slot], slot_of[base_slot], disp)
        elif kind == "opmemdstrip":
            _, _mnemonic, reg_slot, target, _width = item
            p = emit_opcode(_required_key(item))
            emit_mem(p, slot_of[reg_slot], None, target - bytecode_base)
        elif kind == "call":
            # The callee is re-expressed as a signed 32-bit offset from the
            # bytecode base (r15) so the handler recomputes it base-independently;
            # an out-of-range target raises struct.error -> the function stays native.
            p = emit_opcode("call")
            emit_disp(item[1] - bytecode_base, p)
        elif kind == "icall":
            _, reg_slot = item
            p = emit_opcode("icall")
            plain.append(slot_of[reg_slot] ^ p)
        elif kind == "ijmp":
            # Same operand layout as a register-indirect call: one slot byte
            # holding the register whose runtime value is the computed jump target.
            _, reg_slot = item
            p = emit_opcode("ijmp")
            plain.append(slot_of[reg_slot] ^ p)
        elif kind == "callmem":
            _, base_slot, disp = item
            p = emit_opcode("callmem")
            # Reuse the load operand layout; the register field is a placeholder
            # the handler decodes but never uses.
            emit_mem(p, slot_of[0], slot_of[base_slot], disp)
        elif kind == "callmemrip":
            _, target = item
            p = emit_opcode("callmemrip")
            emit_mem(p, slot_of[0], None, target - bytecode_base)
        elif kind == "callmemidx":
            _, base_slot, index_slot, shift, disp = item
            p = emit_opcode("callmemidx")
            # Reuse the scaled-index operand layout; the register field is unused.
            emit_idx(p, slot_of[0], slot_of[base_slot], slot_of[index_slot], shift, disp)
        elif kind == "jmp":
            p = emit_opcode("jmp")
            emit_disp(offsets[item[1]], p)
        elif kind == "jcc":
            p = emit_opcode(_required_key(item))
            emit_disp(offsets[item[2]], p)
        elif kind == "setcc":
            # One destination slot operand (condition + width live in the key).
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[item[2]] ^ p)
        elif kind == "cmov":
            # Destination then source slot operands, position-masked and permuted.
            p = emit_opcode(_required_key(item))
            plain.append(slot_of[item[2]] ^ p)
            plain.append(slot_of[item[3]] ^ p)
        elif kind == "nop":
            emit_opcode("nop")
        elif kind in ("exit", "enter_inner", "inner_exit", "fsave", "frestore"):
            emit_opcode(_required_key(item))
    key = scheme.xor_key
    return bytes(byte ^ key for byte in plain)
