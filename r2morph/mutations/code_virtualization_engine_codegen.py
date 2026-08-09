"""Bytecode encoder and interpreter code generation for the engine VM.

Serializes decoded operand DTOs to encrypted bytecode (:func:`encode_bytecode`),
generates the direct-threaded interpreter assembly (:func:`_interpreter_asm`),
and assembles the whole blob (:func:`build_vm_blob`). Depends only on the
common base layer, the operand models, and the shared asm helper modules.
"""

from __future__ import annotations

import logging
import random
import struct

from r2morph.mutations.code_virtualization_antidebug import (
    _TRACER_ISLAND_LEN,
    patch_tracer_constants,
    timing_fold_asm,
    tracer_const_island_asm,
    tracer_detect_asm,
)
from r2morph.mutations.code_virtualization_dispatch import decode_block, thread_back_jumps
from r2morph.mutations.code_virtualization_engine_common import (
    _DWORD_BROADCAST,
    _FP_ARITH_KINDS,
    _FP_ARITH_MEM_KINDS,
    _FP_CONVERT_KINDS,
    _FP_MEM_KINDS,
    _FP_PACKED_ARITH_KINDS,
    _FP_PACKED_MEM_KINDS,
    _FP_PACKED_WIDTH,
    _FRAME_SIZE,
    _MEM_OP_KINDS,
    _MICROOP_BINOP_KINDS,
    _MICROOP_IMM_KINDS,
    _MICROOP_STACK_KINDS,
    _QWORD_BROADCAST,
    _SHIFT_KINDS,
    GP_REGISTERS,
    RSP_INDEX,
    VMScheme,
    _live_junk_asm,
    pack_immediate,
)
from r2morph.mutations.code_virtualization_engine_frame import DEFAULT_FRAME_LAYOUT, build_frame_layout
from r2morph.mutations.code_virtualization_engine_isa import build_engine_isa_spec
from r2morph.mutations.code_virtualization_engine_microops import (
    MICROOP_ARITH_MNEMONICS,
    emit_arith_imm_microops,
    emit_arith_microops,
    microop_handler_body,
)
from r2morph.mutations.code_virtualization_engine_models import (
    VirtualizedFpArithMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpMemOp,
    VirtualizedFpPackedMemOp,
    VirtualizedFpPackedOp,
    VirtualizedMemOp,
    VirtualizedOp,
)
from r2morph.mutations.code_virtualization_engine_rename import rename_body
from r2morph.mutations.code_virtualization_fold import ARITH_VARIANT_BITS, addr_fold, arith_fold
from r2morph.mutations.code_virtualization_layout import (
    idx_offsets,
    idx_permuted_fields,
    mem_offsets,
    mem_permuted_fields,
    op_offsets,
    op_permuted_fields,
    pair_offsets,
    pair_permuted_fields,
)
from r2morph.mutations.code_virtualization_region_integrity import (
    checksum_prologue_asm,
    compute_build_checksum,
)

logger = logging.getLogger(__name__)


def encode_bytecode(
    ops: list[
        VirtualizedOp
        | VirtualizedMemOp
        | VirtualizedFpMemOp
        | VirtualizedFpArithOp
        | VirtualizedFpConvertOp
        | VirtualizedFpArithMemOp
        | VirtualizedFpPackedOp
        | VirtualizedFpPackedMemOp
    ],
    scheme: VMScheme,
    checksum: int = 0,
    bytecode_base: int = 0,
) -> bytes:
    """Serialize ops to bytecode (per-scheme opcodes), XOR-encrypted by key.

    Immediates are width-sized: 8 bytes for 64-bit ops, 4 for 32-bit.

    ``checksum`` is the expected runtime self-checksum of the interpreter, XORed
    into every opcode so the dispatch (which re-derives it) cancels it on a
    faithful build and misdecodes if the interpreter is patched.
    """
    slot_of = scheme.slot_perm  # logical register index -> shuffled frame slot
    pick = random.Random(scheme.junk_seed).choice  # deterministic per build
    plain = bytearray()

    def emit_opcode(opcode: int) -> int:
        # Mask the opcode byte with its own stream position (the dispatcher
        # subtracts it back out) so the same operation does not encode to the
        # same byte twice and a single-byte XOR of the blob cannot expose the
        # opcode stream. The exit marker is masked the same way and still decodes
        # to a value >= N, so it leaves through the dispatcher's bounds guard.
        # The position is reused to mask this item's operands so they are not all
        # decrypted by one constant key byte a handler trivially reveals.
        position = len(plain) & 0xFF
        plain.append(opcode ^ position ^ checksum)
        return position

    fp = scheme.field_perm

    def emit_fields(position: int, order: list[tuple[str, int]], field_bytes: dict[str, bytes]) -> None:
        # Emit the item's operand fields in this build's permuted order; the
        # handler reads them at the matching offsets via the same layout helper.
        for name, _size in order:
            plain.extend(byte ^ position for byte in field_bytes[name])

    for op in ops:
        if isinstance(op, VirtualizedFpPackedOp):
            # Two raw xmm indices (dst, src); 3-byte item. The mnemonic is the kind.
            position = emit_opcode(pick(scheme.dup[(op.mnemonic, False, _FP_PACKED_WIDTH)]))
            field_bytes = {"dst": bytes([op.dst_index]), "src": bytes([op.src_index])}
            emit_fields(position, pair_permuted_fields("dst", "src", fp), field_bytes)
            continue
        if isinstance(op, VirtualizedFpPackedMemOp):
            # 7-byte reg/base/disp item; ``reg`` is the xmm operand (raw). Always a
            # full 128-bit move.
            position = emit_opcode(pick(scheme.dup[(op.kind, False, _FP_PACKED_WIDTH)]))
            field_bytes = {
                "reg": bytes([op.xmm_index]),
                "base": bytes([slot_of[op.base_index]]),
                "disp": struct.pack("<i", op.disp),
            }
            emit_fields(position, mem_permuted_fields(False, fp), field_bytes)
            continue
        if isinstance(op, VirtualizedFpArithMemOp):
            # ``reg`` is the xmm operand (raw), the op selects the kind/handler. The
            # scaled-index form (index_index >= 0) is a 9-byte reg/base/index/scale/
            # disp item; the rip form (base_index < 0) is a 6-byte reg/offset item
            # whose offset is the constant's signed distance from the bytecode base;
            # the base+disp form is a 7-byte reg/base/disp item.
            if op.index_index >= 0:
                position = emit_opcode(pick(scheme.dup[(f"fparithmem{op.op}idx", False, op.width)]))
                field_bytes = {
                    "reg": bytes([op.xmm_index]),
                    "base": bytes([slot_of[op.base_index]]),
                    "index": bytes([slot_of[op.index_index]]),
                    "shift": bytes([op.scale]),
                    "disp": struct.pack("<i", op.disp),
                }
                emit_fields(position, idx_permuted_fields(False, fp), field_bytes)
            elif op.base_index < 0:
                position = emit_opcode(pick(scheme.dup[(f"fparithmem{op.op}rip", False, op.width)]))
                field_bytes = {
                    "reg": bytes([op.xmm_index]),
                    "disp": struct.pack("<i", op.disp - bytecode_base),
                }
                emit_fields(position, mem_permuted_fields(True, fp), field_bytes)
            else:
                position = emit_opcode(pick(scheme.dup[(f"fparithmem{op.op}", False, op.width)]))
                field_bytes = {
                    "reg": bytes([op.xmm_index]),
                    "base": bytes([slot_of[op.base_index]]),
                    "disp": struct.pack("<i", op.disp),
                }
                emit_fields(position, mem_permuted_fields(False, fp), field_bytes)
            continue
        if isinstance(op, VirtualizedFpConvertOp):
            # xmm index (raw) + GP slot (permuted); the kind carries direction and
            # GP width, the op-key width the FP precision. 3-byte item.
            position = emit_opcode(pick(scheme.dup[(f"{op.direction}{op.gp_width}", False, op.fp_width)]))
            field_bytes = {"xmm": bytes([op.xmm_index]), "gp": bytes([slot_of[op.gp_slot]])}
            emit_fields(position, pair_permuted_fields("xmm", "gp", fp), field_bytes)
            continue
        if isinstance(op, VirtualizedFpArithOp):
            # Two raw xmm indices (dst, src); 3-byte item. The op selects the kind
            # (and thus the handler), so the operands need no op field.
            position = emit_opcode(pick(scheme.dup[(f"fp{op.op}", False, op.width)]))
            field_bytes = {"dst": bytes([op.dst_index]), "src": bytes([op.src_index])}
            emit_fields(position, pair_permuted_fields("dst", "src", fp), field_bytes)
            continue
        if isinstance(op, VirtualizedFpMemOp):
            # ``reg`` holds the xmm index raw (0-15 is a direct save-slot index, not
            # a permuted GP slot). The base+disp form is a 7-byte reg/base/disp item;
            # the rip form is a 6-byte reg/offset item whose offset is the global's
            # signed distance from the bytecode base (out-of-range -> struct.error ->
            # the caller leaves the run native), exactly like a GP load/storerip.
            position = emit_opcode(pick(scheme.dup[(op.kind, False, op.width)]))
            if op.kind.endswith("idx"):
                field_bytes = {
                    "reg": bytes([op.xmm_index]),
                    "base": bytes([slot_of[op.base_index]]),
                    "index": bytes([slot_of[op.index_index]]),
                    "shift": bytes([op.scale]),
                    "disp": struct.pack("<i", op.disp),
                }
                emit_fields(position, idx_permuted_fields(False, fp), field_bytes)
            elif op.kind.endswith("rip"):
                field_bytes = {
                    "reg": bytes([op.xmm_index]),
                    "disp": struct.pack("<i", op.disp - bytecode_base),
                }
                emit_fields(position, mem_permuted_fields(True, fp), field_bytes)
            else:
                field_bytes = {
                    "reg": bytes([op.xmm_index]),
                    "base": bytes([slot_of[op.base_index]]),
                    "disp": struct.pack("<i", op.disp),
                }
                emit_fields(position, mem_permuted_fields(False, fp), field_bytes)
            continue
        if isinstance(op, VirtualizedMemOp):
            position = emit_opcode(pick(scheme.dup[(op.kind, False, op.width)]))
            if op.kind.endswith("rip"):
                # No base slot; the disp field carries the absolute global target,
                # stored as a signed offset from the bytecode base (out-of-range
                # raises struct.error, which the caller turns into "leave native").
                field_bytes = {
                    "reg": bytes([slot_of[op.reg_index]]),
                    "disp": struct.pack("<i", op.disp - bytecode_base),
                }
                emit_fields(position, mem_permuted_fields(True, fp), field_bytes)
            elif op.kind.endswith("idx"):
                field_bytes = {
                    "reg": bytes([slot_of[op.reg_index]]),
                    "base": bytes([slot_of[op.base_index]]),
                    "index": bytes([slot_of[op.index_index]]),
                    "shift": bytes([op.scale]),
                    "disp": struct.pack("<i", op.disp),
                }
                emit_fields(position, idx_permuted_fields(False, fp), field_bytes)
            else:
                field_bytes = {
                    "reg": bytes([slot_of[op.reg_index]]),
                    "base": bytes([slot_of[op.base_index]]),
                    "disp": struct.pack("<i", op.disp),
                }
                emit_fields(position, mem_permuted_fields(False, fp), field_bytes)
            continue
        if op.mnemonic in MICROOP_ARITH_MNEMONICS:
            # Arithmetic lowers to a virtual-stack micro-op sequence instead of one
            # handler, so the native op is data-flow through shared primitives - the
            # reg-reg and immediate forms share the same fold/pop handlers.
            if op.is_immediate:
                emit_arith_imm_microops(op, scheme, slot_of, emit_opcode, emit_fields, pick)
            else:
                emit_arith_microops(op, scheme, slot_of, emit_opcode, emit_fields, pick)
            continue
        position = emit_opcode(pick(scheme.dup[(op.mnemonic, op.is_immediate, op.width)]))
        if op.is_immediate:
            field_bytes = {"dst": bytes([slot_of[op.dst_index]]), "imm": pack_immediate(op.value, op.width)}
        else:
            field_bytes = {"dst": bytes([slot_of[op.dst_index]]), "src": bytes([slot_of[op.value]])}
        emit_fields(position, op_permuted_fields(op.is_immediate, op.width, fp), field_bytes)
    emit_opcode(scheme.exit_opcode)  # no operands
    key = scheme.xor_key
    return bytes(byte ^ key for byte in plain)


def _interpreter_asm(continuation_vaddr: int, scheme: VMScheme, has_fp: bool = False) -> str:
    """Generate the interpreter assembly for one virtualized run.

    Every byte fetched from the bytecode is XOR-decrypted with the scheme key
    before use; opcodes are compared against the scheme's randomized values.

    When ``has_fp`` is set, the prologue spills all 16 xmm registers into the
    frame's xmm save area and the epilogue reloads them, so a run that moves FP
    data through xmm preserves it; a GP-only run skips both.
    """
    key = scheme.xor_key
    key_qword = hex((key * _QWORD_BROADCAST) & 0xFFFFFFFFFFFFFFFF)
    key_dword = hex((key * _DWORD_BROADCAST) & 0xFFFFFFFF)
    # This build's ISA personality: the arithmetic-fold variant every operation
    # handler uses (variant 0 == the shared canonical fold, byte-identical).
    isa = build_engine_isa_spec(scheme.engine_isa_seed)
    # Each opcode index gets its own handler instance; an operation with two
    # indices is emitted twice, each copy carrying different junk, so the
    # opcode->operation map is not one-to-one and the duplicates share no byte
    # signature. ``total`` is the dispatch-table width and the bounds-guard limit.
    index_to_key = {index: op_key for op_key, indices in scheme.dup.items() for index in indices}
    total = len(index_to_key)
    junk_rng = random.Random(scheme.junk_seed)
    # This build's frame-region offsets (checksum/xmm/vsp/vstack): relocated per
    # build so no fixed frame map of the VM's state transfers across samples. The
    # frame size stays _FRAME_SIZE, so the entry signature is unchanged.
    layout = (
        build_frame_layout(_FRAME_SIZE, random.Random(scheme.frame_seed)) if scheme.frame_seed else DEFAULT_FRAME_LAYOUT
    )

    def mem_addr_prologue() -> str:
        # Shared head of every memory handler: reg slot [rsi+1] -> r8, base slot
        # [rsi+2] -> r9, signed disp32 [rsi+3..6] -> rax. Each operand is un-masked
        # by key XOR r13b (the stream position); the disp broadcasts r13b to 32 bits
        # before sign-extending. The effective address is the base slot's current
        # value plus the displacement, folded with the shared MBA add (no literal
        # address add), left in r10.
        off = mem_offsets(False, scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
            f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            "  movsxd rax, eax\n  mov r10, qword ptr [rsp + r9*8]\n" + addr_fold("rax", "rcx", key, isa.addr_variant)
        )

    def mem_riprel_prologue() -> str:
        # rip-relative head: reg slot [rsi+1] -> r8, signed offset32 [rsi+2..5] (the
        # global's distance from the bytecode base). The address is r15 (the bytecode
        # base, held for the whole run) plus that offset, folded with MBA; so the
        # global is reached base-independently exactly like the original [rip+disp].
        off = mem_offsets(True, scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
            f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            "  movsxd rax, eax\n  mov r10, r15\n" + addr_fold("rax", "rcx", key, isa.addr_variant)
        )

    def mem_idx_prologue() -> str:
        # Indexed head: reg [rsi+1]->r8, base [rsi+2]->r9, index [rsi+3]->r11,
        # scale-shift [rsi+4]->cl, signed disp32 [rsi+5..8]. Computes
        # base + index*(2**scale) + disp into r10, both adds folded with MBA.
        off = idx_offsets(False, scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            f"  movzx r11d, byte ptr [rsi+{off['index']}]\n  xor r11b, {key}\n  xor r11b, r13b\n"
            f"  movzx ecx, byte ptr [rsi+{off['shift']}]\n  xor cl, {key}\n  xor cl, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r10d, {key_dword}\n  xor eax, r10d\n"
            f"  movzx r10d, r13b\n  imul r10d, r10d, {hex(_DWORD_BROADCAST)}\n  xor eax, r10d\n"
            "  movsxd rax, eax\n  mov r10, qword ptr [rsp + r11*8]\n  shl r10, cl\n"
            "  mov r11, qword ptr [rsp + r9*8]\n"
            + addr_fold("r11", "rcx", key, isa.addr_variant)
            + addr_fold("rax", "rcx", key, isa.addr_variant)
        )

    def mem_handler_body(kind: str, width: int, arith_variant: int) -> str:
        # base+disp items are 7 bytes (opcode+reg+base+disp32); rip-relative items
        # are 6 (opcode+reg+offset32); indexed items are 9 (opcode+reg+base+index+
        # scale+disp32). r10 holds the address in every case.
        if kind.endswith("rip"):
            kind, body, advance = kind[: -len("rip")], mem_riprel_prologue(), 6
        elif kind.endswith("idx"):
            kind, body, advance = kind[: -len("idx")], mem_idx_prologue(), 9
        else:
            body, advance = mem_addr_prologue(), 7
        if kind == "load":
            body += "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
            body += "  mov qword ptr [rsp + r8*8], rax\n"
        elif kind == "store":
            if width == 64:
                body += "  mov rax, qword ptr [rsp + r8*8]\n  mov qword ptr [r10], rax\n"
            else:
                body += "  mov eax, dword ptr [rsp + r8*8]\n  mov dword ptr [r10], eax\n"
        elif kind == "lea":
            # Store the effective address itself (no dereference). A 32-bit dst
            # truncates to the low 32 bits, zero-extended into the slot.
            if width == 32:
                body += "  mov r10d, r10d\n"
            body += "  mov qword ptr [rsp + r8*8], r10\n"
        elif kind.startswith(("movzx", "movsx")):
            # Zero/sign-extend a byte or word from [addr] into the destination slot.
            # movzx always zero-extends the same regardless of dst width; movsx's
            # target register depends on whether the destination is 32- or 64-bit.
            size_word = "byte" if kind.endswith("b") else "word"
            if kind.startswith("movzx"):
                body += f"  movzx eax, {size_word} ptr [r10]\n"
            elif width == 64:
                body += f"  movsx rax, {size_word} ptr [r10]\n"
            else:
                body += f"  movsx eax, {size_word} ptr [r10]\n"
            body += "  mov qword ptr [rsp + r8*8], rax\n"
        else:
            # mem<op>: reg = reg <op> [addr], computed with no literal native op via
            # the shared MBA builder (flags dead by the engine's precondition). Load
            # the memory source into rax, the register into r10, then fold.
            mnemonic = kind[len("mem") :]
            body += "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
            if mnemonic == "sub":
                body += "  neg rax\n"
            body += "  mov r10, qword ptr [rsp + r8*8]\n" if width == 64 else "  mov r10d, dword ptr [rsp + r8*8]\n"
            body += arith_fold(mnemonic, key, arith_variant)
            if width == 64:
                body += "  mov qword ptr [rsp + r8*8], r10\n"
            else:
                body += "  mov r10d, r10d\n  mov qword ptr [rsp + r8*8], r10\n"
        return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"

    def fp_base_addr_prologue() -> str:
        # Shared head of every base+disp FP memory handler. Mirrors mem_addr_prologue
        # (base slot value + sign-extended disp32 folded with MBA -> r10, the
        # program's real address) and additionally computes the xmm save-slot address
        # from the "reg" field (xmm index): rsp + layout.xmm_offset + index*16 -> r11.
        # The epilogue reloads the save slots into the architectural xmm registers.
        off = mem_offsets(False, scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
            f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            "  movsxd rax, eax\n  mov r10, qword ptr [rsp + r9*8]\n"
            + addr_fold("rax", "rcx", key, isa.addr_variant)
            + f"  shl r8, 4\n  lea r11, [rsp + r8 + {layout.xmm_offset}]\n"
        )

    def fp_riprel_addr_prologue() -> str:
        # rip-relative head: xmm index ("reg") -> r8, signed offset32 -> rax, the
        # program address r15 (bytecode base) + offset folded with MBA -> r10, and
        # the xmm save-slot address -> r11. Mirrors mem_riprel_prologue.
        off = mem_offsets(True, scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
            f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            "  movsxd rax, eax\n  mov r10, r15\n"
            + addr_fold("rax", "rcx", key, isa.addr_variant)
            + f"  shl r8, 4\n  lea r11, [rsp + r8 + {layout.xmm_offset}]\n"
        )

    def fp_idx_addr_prologue() -> str:
        # Scaled-index head: reuses the GP indexed prologue (base + index*2**scale +
        # disp -> r10, xmm index preserved in r8) and adds the xmm save-slot address
        # -> r11, matching the base and rip prologues' register contract.
        return mem_idx_prologue() + f"  shl r8, 4\n  lea r11, [rsp + r8 + {layout.xmm_offset}]\n"

    def fp_mem_handler_body(kind: str, width: int) -> str:
        # Scalar FP load/store: base+disp (7-byte item), rip-relative (6-byte), or
        # scaled-index (9-byte). xmm0 is free scratch (its program value lives in
        # save slot 0 and is reloaded on exit). A load goes through the scalar move
        # then writes the whole slot via movups, so movsd/movss's upper-lane zeroing
        # is reproduced in the reloaded register; a store reads the slot and writes
        # only the scalar to memory. r10 = program address, r11 = xmm save-slot addr.
        move = "movsd" if width == 64 else "movss"
        if kind.endswith("idx"):
            kind, body, advance = kind[: -len("idx")], fp_idx_addr_prologue(), 9
        elif kind.endswith("rip"):
            kind, body, advance = kind[: -len("rip")], fp_riprel_addr_prologue(), 6
        else:
            body, advance = fp_base_addr_prologue(), 7
        if kind == "fpload":
            body += f"  {move} xmm0, [r10]\n  movups xmmword ptr [r11], xmm0\n"
        else:
            body += f"  movups xmm0, xmmword ptr [r11]\n  {move} [r10], xmm0\n"
        return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"

    def fp_arith_mem_handler_body(kind: str, width: int) -> str:
        # Scalar FP arithmetic with a memory source, base+disp (7-byte item) or
        # rip-relative (6-byte). The dst xmm slot loads via movups (preserving the
        # upper lane), the real scalar {op}{sd,ss} folds the memory operand into the
        # low lane (scalar mem operands need no alignment), and the result writes
        # back to the slot.
        suffix = "sd" if width == 64 else "ss"
        if kind.endswith("idx"):
            kind, body, advance = kind[: -len("idx")], fp_idx_addr_prologue(), 9
        elif kind.endswith("rip"):
            kind, body, advance = kind[: -len("rip")], fp_riprel_addr_prologue(), 6
        else:
            body, advance = fp_base_addr_prologue(), 7
        op = kind[len("fparithmem") :]
        body += f"  movups xmm0, xmmword ptr [r11]\n  {op}{suffix} xmm0, [r10]\n  movups xmmword ptr [r11], xmm0\n"
        return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"

    def fp_arith_handler_body(kind: str, width: int) -> str:
        # Scalar reg-reg FP arithmetic. The item carries two raw xmm indices (dst,
        # src) in this build's pair order; each selects a 16-byte slot in the xmm
        # save area. Both operands load via movups (full 128), the real scalar
        # {op}{sd|ss} computes the low lane (the dst's upper lanes ride through the
        # movups round trip, matching the hardware scalar form), and the result is
        # stored back to the dst slot. No MBA: FP arithmetic has no boolean rewrite.
        off = pair_offsets("dst", "src", scheme.field_perm)
        op = kind[len("fp") :]
        suffix = "sd" if width == 64 else "ss"
        return (
            f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            f"  shl r8, 4\n  lea r10, [rsp + r8 + {layout.xmm_offset}]\n"
            f"  shl r9, 4\n  lea r11, [rsp + r9 + {layout.xmm_offset}]\n"
            "  movups xmm0, xmmword ptr [r10]\n  movups xmm1, xmmword ptr [r11]\n"
            f"  {op}{suffix} xmm0, xmm1\n  movups xmmword ptr [r10], xmm0\n"
            "  add rsi, 3\n  jmp vm_dispatch\n"
        )

    def fp_convert_handler_body(kind: str, fp_width: int) -> str:
        # Int<->float conversion. The kind is direction (6 chars) + GP width; the
        # item carries the xmm index (raw) and the GP slot. cvti2f reads the GP slot
        # (eax for a 32-bit source, rax for 64-bit), loads the dst xmm slot first so
        # cvtsi2{sd,ss} only rewrites the low lane (preserving the upper), and stores
        # back. cvtf2i loads the source xmm and writes the GP slot via cvtt{sd,ss}2si
        # (eax for 32-bit, which zero-extends and saturates out-of-int32 doubles to
        # 0x80000000; rax for 64-bit).
        direction, gp_width = kind[:6], int(kind[6:])
        off = pair_offsets("xmm", "gp", scheme.field_perm)
        suffix = "sd" if fp_width == 64 else "ss"
        body = (
            f"  movzx r8d, byte ptr [rsi+{off['xmm']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['gp']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            f"  shl r8, 4\n  lea r10, [rsp + r8 + {layout.xmm_offset}]\n"
        )
        if direction == "cvti2f":
            body += "  movups xmm0, xmmword ptr [r10]\n"
            if gp_width == 64:
                body += f"  mov rax, qword ptr [rsp + r9*8]\n  cvtsi2{suffix} xmm0, rax\n"
            else:
                body += f"  mov eax, dword ptr [rsp + r9*8]\n  cvtsi2{suffix} xmm0, eax\n"
            body += "  movups xmmword ptr [r10], xmm0\n"
        else:
            body += "  movups xmm0, xmmword ptr [r10]\n"
            if gp_width == 64:
                body += f"  cvtt{suffix}2si rax, xmm0\n"
            else:
                body += f"  cvtt{suffix}2si eax, xmm0\n"
            body += "  mov qword ptr [rsp + r9*8], rax\n"
        return body + "  add rsi, 3\n  jmp vm_dispatch\n"

    def fp_packed_arith_handler_body(mnemonic: str) -> str:
        # Packed reg-reg arithmetic. Both operand slots load via movups (full 128),
        # the real packed op computes all lanes (no upper-lane preservation, unlike
        # the scalar form), and the result stores back to the dst slot.
        off = pair_offsets("dst", "src", scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            f"  shl r8, 4\n  lea r10, [rsp + r8 + {layout.xmm_offset}]\n"
            f"  shl r9, 4\n  lea r11, [rsp + r9 + {layout.xmm_offset}]\n"
            "  movups xmm0, xmmword ptr [r10]\n  movups xmm1, xmmword ptr [r11]\n"
            f"  {mnemonic} xmm0, xmm1\n  movups xmmword ptr [r10], xmm0\n"
            "  add rsi, 3\n  jmp vm_dispatch\n"
        )

    def fp_packed_mem_handler_body(kind: str) -> str:
        # Packed 128-bit load/store, base+disp. The whole 16-byte slot moves via
        # movups (no alignment assumption). r10 = program address, r11 = xmm slot.
        body = fp_base_addr_prologue()
        if kind == "fppload":
            body += "  movups xmm0, xmmword ptr [r10]\n  movups xmmword ptr [r11], xmm0\n"
        else:
            body += "  movups xmm0, xmmword ptr [r11]\n  movups xmmword ptr [r10], xmm0\n"
        return body + "  add rsi, 7\n  jmp vm_dispatch\n"

    def handler_body(mnemonic: str, is_immediate: bool, width: int, arith_variant: int) -> str:
        if mnemonic in _MICROOP_STACK_KINDS or mnemonic in _MICROOP_BINOP_KINDS or mnemonic in _MICROOP_IMM_KINDS:
            return microop_handler_body(mnemonic, width, key, layout.vsp_offset, layout.vstack_base, arith_variant)
        if mnemonic in _FP_PACKED_ARITH_KINDS:
            return fp_packed_arith_handler_body(mnemonic)
        if mnemonic in _FP_PACKED_MEM_KINDS:
            return fp_packed_mem_handler_body(mnemonic)
        if mnemonic in _FP_ARITH_MEM_KINDS:
            return fp_arith_mem_handler_body(mnemonic, width)
        if mnemonic in _FP_CONVERT_KINDS:
            return fp_convert_handler_body(mnemonic, width)
        if mnemonic in _FP_ARITH_KINDS:
            return fp_arith_handler_body(mnemonic, width)
        if mnemonic in _FP_MEM_KINDS:
            return fp_mem_handler_body(mnemonic, width)
        if mnemonic in _MEM_OP_KINDS:
            return mem_handler_body(mnemonic, width, arith_variant)
        # Operands carry the opcode's stream position too (r13 still holds it from
        # the dispatch), so each is un-masked by both the key and r13b - there is
        # no lone constant-key decrypt repeated across every handler.
        off = op_offsets(is_immediate, width, scheme.field_perm)
        decrypt_dst = f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        if is_immediate and width == 64:
            load = (
                f"  mov rax, qword ptr [rsi+{off['imm']}]\n  mov r10, {key_qword}\n  xor rax, r10\n"
                f"  movzx r10, r13b\n  mov r11, {hex(_QWORD_BROADCAST)}\n  imul r10, r11\n  xor rax, r10\n"
            )
            advance = "  add rsi, 10\n"
        elif is_immediate:
            load = (
                f"  mov eax, dword ptr [rsi+{off['imm']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
                f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            )
            advance = "  add rsi, 6\n"
        else:
            load = f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            load += "  mov rax, qword ptr [rsp + r9*8]\n" if width == 64 else "  mov eax, dword ptr [rsp + r9*8]\n"
            advance = "  add rsi, 3\n"

        # rax/eax now holds the source value (an immediate, or a register for mov).
        # Reg-reg and immediate arithmetic no longer reach here - they lower to the
        # micro-op stack primitives - so only mov and the immediate shifts remain.
        if mnemonic in _SHIFT_KINDS:
            # rax/eax holds the imm8 shift count; drive the native shift by cl
            # (the CPU masks cl to width-1 exactly as the original `shl reg, imm8`
            # did). Flags dead by the engine precondition, so the literal shift is
            # safe. ponytail: literal shift (no MBA) - the region VM's shift
            # handlers are literal too; coverage is the goal, not another layer.
            reg = "r10" if width == 64 else "r10d"
            load_slot = "  mov r10, qword ptr [rsp + r8*8]\n" if width == 64 else "  mov r10d, dword ptr [rsp + r8*8]\n"
            store_slot = (
                "  mov qword ptr [rsp + r8*8], r10\n"
                if width == 64
                else "  mov r10d, r10d\n  mov qword ptr [rsp + r8*8], r10\n"
            )
            apply = f"  mov ecx, eax\n{load_slot}  {mnemonic} {reg}, cl\n{store_slot}"
        else:
            # mov: store the source verbatim (the only remaining single-handler GP op).
            apply = "  mov qword ptr [rsp + r8*8], rax\n"
        return decrypt_dst + load + apply + advance + "  jmp vm_dispatch\n"

    slot = scheme.slot_perm  # logical register index -> shuffled frame slot
    lines = [f"vm_entry:\n  sub rsp, {_FRAME_SIZE}\n"]
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov qword ptr [rsp + {slot[index] * 8}], {name}\n")
    # Empty the virtual operand stack for the micro-op handlers (pointer word = 0).
    lines.append(f"  mov qword ptr [rsp + {layout.vsp_offset}], 0\n")
    if has_fp:
        # Spill all 16 xmm registers into the save area so FP handlers can route
        # data through it; movups needs no alignment. Only emitted for FP runs.
        for xmm in range(16):
            lines.append(f"  movups xmmword ptr [rsp + {layout.xmm_offset + xmm * 16}], xmm{xmm}\n")
    # Anti-tamper: checksum the interpreter's own code into a frame slot the
    # dispatch folds into every opcode decrypt; runs after the register spill. The
    # trailing offset table (encrypted after assembly) is excluded from the span.
    lines.append(checksum_prologue_asm(key, slot=layout.checksum_offset, end_label="vm_table"))
    # Timing anti-debug woven into the same checksum slot: a single-stepped run
    # folds 0xFF into the byte and misdecodes every opcode; an untraced run folds
    # 0x00 (the counter reads sit inside the checksummed range, so no encoder or
    # checksum change is needed and the benign build is bit-identical).
    lines.append(timing_fold_asm(key, slot=layout.checksum_offset))
    # Tracer anti-debug into the same checksum slot: an attached ptrace debugger
    # (TracerPid != 0) folds 0xFF and misdecodes every opcode; an untraced native
    # run and a Unicorn emulation both fold 0x00, so the benign build is unchanged.
    lines.append(tracer_detect_asm(slot=layout.checksum_offset))
    poly_rng = random.Random(scheme.table_key)
    # Undo the opcode byte's position mask and fold in the key and the runtime
    # self-checksum the encoder pre-biased the opcode with, so a patched interpreter
    # misdecodes; the bounds guard then routes any out-of-range byte (the exit
    # marker) to vm_exit.
    opcode_xors = [
        f"  xor al, {key}\n",
        "  xor al, r13b\n",
        f"  xor al, byte ptr [rsp + {layout.checksum_offset}]\n",
    ]
    bounds = f"  cmp al, {total}\n  jae vm_exit\n"

    def make_decode() -> str:
        return decode_block(
            opcode_xors=opcode_xors,
            bounds=bounds,
            # The stored offsets are XOR-encrypted (not a plaintext switch) and the
            # table key is diffused with the self-checksum (broadcast to 32 bits),
            # so tampering corrupts handler resolution, not just opcodes.
            table_load="  lea r14, [rip + vm_table]\n  mov eax, dword ptr [r14 + rax*4]\n",
            table_xors=[
                f"  xor eax, {hex(scheme.table_key)}\n",
                f"  movzx ecx, byte ptr [rsp + {layout.checksum_offset}]\n  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n",
            ],
            rng=poly_rng,
        )

    # r15 holds the bytecode base; r13/r14 are free scratch between handlers.
    entry_setup = (
        f"  lea rax, [rsp + {_FRAME_SIZE}]\n"
        f"  mov qword ptr [rsp + {slot[RSP_INDEX] * 8}], rax\n"
        "  lea rsi, [rip + bytecode]\n  mov r15, rsi\n"
    )
    # The decode is inlined at the entry and (via thread_back_jumps below) at every
    # handler tail, so there is no central dispatcher node - each handler decodes the
    # next opcode and jumps straight to it. Shuffling the order-independent XOR groups
    # keeps every copy the same length, so assembled size and executed instruction
    # count are unchanged.
    lines.append(entry_setup + make_decode())

    # Emit the handler instances in a per-build shuffled order rather than opcode
    # order: the dispatch table addresses each by label (h_{index} - vm_table), so
    # file order is free, and shuffling it keeps the physical layout from leaking the
    # opcode ordering a positional handler-matcher would read off the block sequence.
    emit_order = list(range(total))
    random.Random(scheme.body_seed ^ 0x9E3779B9).shuffle(emit_order)
    for index in emit_order:
        mnemonic, is_immediate, width = index_to_key[index]
        # Give each *instance* of an arithmetic handler its own MBA fold (drawn from
        # the build's isa seed and the handler index), so duplicate handlers for one
        # operation diverge semantically, not only in junk and register allocation.
        # The arithmetic fold has no cross-handler encoding coupling; the addressing
        # personality stays per-build. engine_isa_seed 0 keeps the canonical fold, so
        # builds that opt out of the ISA personality stay byte-identical.
        arith_variant = (
            random.Random((scheme.engine_isa_seed << 16) ^ index).randrange(1 << ARITH_VARIANT_BITS)
            if scheme.engine_isa_seed
            else isa.arith_variant
        )
        # Reachable head junk makes duplicate handlers diverge in executed code, and
        # a per-handler scratch-register bijection makes the body itself diverge, so
        # duplicate handlers share neither junk nor register-allocation fingerprint.
        body = rename_body(
            handler_body(mnemonic, is_immediate, width, arith_variant), random.Random(scheme.body_seed ^ index)
        )
        lines.append(f"h_{index}:\n{_live_junk_asm(junk_rng, index)}{body}")

    lines.append("vm_exit:\n")
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov {name}, qword ptr [rsp + {slot[index] * 8}]\n")
    if has_fp:
        for xmm in range(16):
            lines.append(f"  movups xmm{xmm}, xmmword ptr [rsp + {layout.xmm_offset + xmm * 16}]\n")
    lines.append(f"  add rsp, {_FRAME_SIZE}\n  jmp {hex(continuation_vaddr)}\n")

    table = "".join(f"  .long h_{index} - vm_table\n" for index in range(total))
    # The tracer-constant island trails the table (outside the checksummed span,
    # before the appended bytecode); build_vm_blob patches it once the checksum is
    # known and accounts for its length when locating the table.
    lines.append(f"vm_table:\n{table}{tracer_const_island_asm()}bytecode:\n")
    # Thread the dispatch: every handler tail ends with a back jump to the (now
    # removed) central dispatcher; splice a freshly shuffled decode copy in for each
    # so control flows handler -> decode -> next handler with no shared hub block
    # and no two copies sharing a byte layout.
    return thread_back_jumps("".join(lines), make_decode)


def build_vm_blob(
    ops: list[
        VirtualizedOp
        | VirtualizedMemOp
        | VirtualizedFpMemOp
        | VirtualizedFpArithOp
        | VirtualizedFpConvertOp
        | VirtualizedFpArithMemOp
        | VirtualizedFpPackedOp
        | VirtualizedFpPackedMemOp
    ],
    cave_vaddr: int,
    continuation_vaddr: int,
    scheme: VMScheme,
) -> bytes | None:
    """
    Assemble the interpreter at ``cave_vaddr`` and append the encrypted bytecode.

    The interpreter's ``lea rsi, [rip + bytecode]`` resolves to the byte
    immediately after the assembled code, where the bytecode is appended.
    Returns ``None`` if keystone is unavailable or assembly fails - the
    caller then leaves the function untouched.
    """
    try:
        import keystone
    except ImportError:
        logger.warning("keystone unavailable; cannot virtualize")
        return None

    has_fp = any(
        isinstance(
            op,
            (
                VirtualizedFpMemOp,
                VirtualizedFpArithOp,
                VirtualizedFpConvertOp,
                VirtualizedFpArithMemOp,
                VirtualizedFpPackedOp,
                VirtualizedFpPackedMemOp,
            ),
        )
        for op in ops
    )
    asm = _interpreter_asm(continuation_vaddr, scheme, has_fp)
    try:
        engine = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, _ = engine.asm(asm, cave_vaddr)
    except keystone.KsError as exc:
        logger.debug("VM interpreter assembly failed: %s", exc)
        return None
    if not encoding:
        logger.debug("VM interpreter assembly produced no bytes")
        return None

    data = bytearray(encoding)
    # The dispatch table is the tail ``total`` 32-bit entries of the assembled
    # interpreter; XOR-encrypt each in place so the handler addresses are not a
    # plaintext jump table (the dispatch decrypts them at runtime; keystone
    # cannot XOR a label difference it computes itself). The self-checksum spans
    # everything up to the table, so the encryption below does not perturb it;
    # the encoder folds it into the opcodes and the table key is diffused with it.
    total = sum(len(indices) for indices in scheme.dup.values())
    # The assembled interpreter ends with the table followed by the tracer-constant
    # island; both trail vm_table and are excluded from the checksummed span.
    island_start = len(data) - _TRACER_ISLAND_LEN
    table_start = island_start - total * 4
    checksum = compute_build_checksum(bytes(data[:table_start]), scheme.xor_key)
    table_key = scheme.table_key ^ (checksum * 0x01010101)
    for entry_index in range(total):
        offset = table_start + entry_index * 4
        encrypted = int.from_bytes(data[offset : offset + 4], "little") ^ table_key
        data[offset : offset + 4] = encrypted.to_bytes(4, "little")
    patch_tracer_constants(data, island_start, checksum)
    # The bytecode is appended right after the interpreter, so its base is the cave
    # plus the assembled interpreter length; rip-relative globals are stored as a
    # signed 32-bit offset from it. A target too far to express leaves the run native.
    bytecode_base = cave_vaddr + len(data)
    try:
        bytecode = encode_bytecode(ops, scheme, checksum, bytecode_base)
    except struct.error:
        logger.debug("rip-relative target out of 32-bit range; leaving run native")
        return None
    return bytes(data) + bytecode
