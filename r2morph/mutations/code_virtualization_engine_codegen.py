"""Bytecode encoder and interpreter code generation for the engine VM.

Serializes decoded operand DTOs to encrypted bytecode (:func:`encode_bytecode`),
generates the direct-threaded interpreter assembly (:func:`_interpreter_asm`),
and assembles the whole blob (:func:`build_vm_blob`). Depends only on the
common base layer, the operand models, and the shared asm helper modules.
"""

from __future__ import annotations

import r2morph.core.randomness as random
from r2morph.mutations.code_virtualization_antidebug import (
    tracer_const_island_asm,
)
from r2morph.mutations.code_virtualization_bootstrap import build_bootstrap_asm
from r2morph.mutations.code_virtualization_dispatch import decode_block, thread_back_jumps
from r2morph.mutations.code_virtualization_engine_common import (
    GP_REGISTERS,
    RSP_INDEX,
    VMScheme,
    _live_junk_asm,
    gp_save_order,
)
from r2morph.mutations.code_virtualization_engine_encoder import EngineOp
from r2morph.mutations.code_virtualization_engine_encoder import encode_bytecode as _encode_bytecode
from r2morph.mutations.code_virtualization_engine_frame import DEFAULT_FRAME_LAYOUT, build_frame_layout
from r2morph.mutations.code_virtualization_engine_handlers import EngineHandlerGenerator
from r2morph.mutations.code_virtualization_engine_isa import build_engine_isa_spec
from r2morph.mutations.code_virtualization_engine_rename import rename_body
from r2morph.mutations.code_virtualization_fold import ARITH_VARIANT_BITS
from r2morph.mutations.code_virtualization_region_integrity import (
    checksum_prologue_asm,
)
from r2morph.mutations.code_virtualization_region_regcipher import cipher_register_slots


def encode_bytecode(
    ops: list[EngineOp],
    scheme: VMScheme,
    checksum: int = 0,
    bytecode_base: int = 0,
) -> bytes:
    """Serialize operations to engine bytecode."""
    return _encode_bytecode(ops, scheme, checksum, bytecode_base)


def _interpreter_asm(continuation_vaddr: int, scheme: VMScheme, has_fp: bool = False) -> str:
    """Generate the interpreter assembly for one virtualized run.

    Every byte fetched from the bytecode is XOR-decrypted with the scheme key
    before use; opcodes are compared against the scheme's randomized values.

    When ``has_fp`` is set, the prologue spills all 16 xmm registers into the
    frame's xmm save area and the epilogue reloads them, so a run that moves FP
    data through xmm preserves it; a GP-only run skips both.
    """
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
    # The frame size and internal regions vary per build while remaining self-consistent.
    frame_size = scheme.frame_size
    layout = (
        build_frame_layout(frame_size, random.Random(scheme.frame_seed)) if scheme.frame_seed else DEFAULT_FRAME_LAYOUT
    )
    handlers = EngineHandlerGenerator(scheme, layout, isa)

    slot = scheme.slot_perm  # logical register index -> shuffled frame slot
    save_order = gp_save_order(scheme.junk_seed ^ 0x51A7E)
    lines = [f"vm_entry:\n  sub rsp, {frame_size}\n"]
    for index in save_order:
        lines.append(f"  mov qword ptr [rsp + {slot[index] * 8}], {GP_REGISTERS[index]}\n")
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
    lines.append(
        checksum_prologue_asm(
            scheme.xor_key,
            slot=layout.checksum_offset,
            end_label="vm_table",
            bytewise=scheme.checksum_bytewise,
        )
    )
    poly_rng = random.Random(scheme.table_key)
    # Undo the opcode byte's position mask and the runtime self-checksum the whole-blob
    # pass XORed in: a faithful interpreter cancels the checksum and a tampered one
    # misdecodes. No separate constant key term -- the byte key IS the checksum -- so
    # the opcode decrypt exposes no operand-cipher literal.
    opcode_xors = [
        "  xor al, r13b\n",
        f"  xor al, byte ptr [rsp + {layout.checksum_offset}]\n",
    ]
    bounds = f"  cmp al, {total}\n  jae vm_exit\n"
    # Keep the live vPC, bytecode base, and position opaque at the indirect jump;
    # the handler restores the raw values before it reads or advances the record.
    # State masking is separate from operand masking and includes the caller's stack
    # address, so the state mask has no build-time value an encoder could expose.
    state_key = f"qword ptr [rsp + {layout.state_qword_offset}]"
    state_decode = f"  xor rsi, {state_key}\n" f"  xor r15, {state_key}\n" f"  xor r13, {state_key}\n"

    def make_decode() -> str:
        return decode_block(
            opcode_xors=opcode_xors,
            bounds=bounds,
            # The stored offsets are XOR-encrypted (not a plaintext switch) with the
            # self-checksum broadcast to 32 bits -- a value the decompiler cannot fold,
            # so the decrypt exposes no build-constant table key -- and tampering
            # corrupts handler resolution, not just opcodes.
            table_load="  lea r14, [rip + vm_table]\n  mov eax, dword ptr [r14 + rax*4]\n",
            table_xors=[
                (
                    f"  movzx ecx, byte ptr [rsp + {layout.checksum_offset}]\n"
                    f"  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n{state_decode}"
                ),
            ],
            rng=poly_rng,
        )

    # r15 holds the bytecode base; r13/r14 are free scratch between handlers.
    entry_setup = (
        f"  lea rax, [rsp + {frame_size}]\n"
        f"  xor rax, qword ptr [rsp + {layout.key_qword_offset}]\n"
        f"  mov qword ptr [rsp + {slot[RSP_INDEX] * 8}], rax\n"
        "  lea rsi, [rip + bytecode]\n  mov r15, rsi\n"
    )
    # The decode is inlined at the entry and (via thread_back_jumps below) at every
    # handler tail, so there is no central dispatcher node - each handler decodes the
    # next opcode and jumps straight to it. Shuffling the order-independent XOR groups
    # keeps every copy the same length, so assembled size and executed instruction
    # count are unchanged.
    key_setup = (
        f"  movzx eax, byte ptr [rsp + {layout.checksum_offset}]\n  imul eax, eax, 0x1010101\n"
        f"  mov dword ptr [rsp + {layout.key_dword_offset}], eax\n"
        f"  movzx rax, byte ptr [rsp + {layout.checksum_offset}]\n"
        "  mov rcx, 0x0101010101010101\n  imul rax, rcx\n"
        f"  mov qword ptr [rsp + {layout.key_qword_offset}], rax\n"
        f"  lea rax, [rsp + {frame_size}]\n"
        "  ror rax, 17\n"
        f"  xor rax, qword ptr [rsp + {layout.key_qword_offset}]\n"
        f"  mov qword ptr [rsp + {layout.state_qword_offset}], rax\n"
    )
    encrypt_slots = "".join(
        f"  mov rcx, qword ptr [rsp + {slot[index] * 8}]\n"
        "  xor rcx, rax\n"
        f"  mov qword ptr [rsp + {slot[index] * 8}], rcx\n"
        for index in save_order
    )
    bootstrap, bootstrap_table = build_bootstrap_asm(
        layout.checksum_offset,
        scheme.junk_seed,
        key_setup + encrypt_slots + entry_setup + make_decode(),
    )
    lines.append(bootstrap)
    handler_start = len(lines)

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
        handlers.set_record_padding(scheme.record_padding[index] if scheme.record_padding else 0)
        body = rename_body(
            handlers.handler_body(
                mnemonic,
                is_immediate,
                width,
                arith_variant,
                body_variant=(random.Random(scheme.body_seed ^ (index << 1)).randrange(4) if scheme.body_seed else 0),
            ),
            random.Random(scheme.body_seed ^ index),
        )
        lines.append(f"h_{index}:\n{state_decode}{_live_junk_asm(junk_rng, index)}{body}")

    lines.append("vm_exit:\n")
    for index in save_order:
        lines.append(f"  mov {GP_REGISTERS[index]}, qword ptr [rsp + {slot[index] * 8}]\n")
    if has_fp:
        for xmm in range(16):
            lines.append(f"  movups xmm{xmm}, xmmword ptr [rsp + {layout.xmm_offset + xmm * 16}]\n")
    lines.append(f"  add rsp, {frame_size}\n  jmp {hex(continuation_vaddr)}\n")

    table = "".join(f"  .long h_{index} - vm_table\n" for index in range(total))
    # The bootstrap table and tracer-constant island trail the main table, outside
    # the checksummed span and before the appended bytecode.
    lines.append(f"vm_table:\n{table}{bootstrap_table}{tracer_const_island_asm()}bytecode:\n")
    # Thread the dispatch: every handler tail ends with a back jump to the (now
    # removed) central dispatcher; splice a freshly shuffled decode copy in for each
    # so control flows handler -> decode -> next handler with no shared hub block
    # and no two copies sharing a byte layout.
    interpreter = "".join(lines[:handler_start]) + cipher_register_slots(
        "".join(lines[handler_start:]),
        frozenset(index * 8 for index in slot),
        layout.key_qword_offset,
    )
    return thread_back_jumps(interpreter, make_decode)
