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
import re
import struct
from importlib import import_module

import r2morph.core.randomness as random
from r2morph.mutations.code_virtualization_antidebug import (
    _TRACER_ISLAND_LEN,
    patch_tracer_constants,
    tracer_const_island_asm,
)
from r2morph.mutations.code_virtualization_bootstrap import (
    BOOTSTRAP_TABLE_SIZE,
    build_bootstrap_asm,
    encrypt_bootstrap_table,
    table_entry_key,
    table_key_mix,
)
from r2morph.mutations.code_virtualization_dispatch import decode_block, thread_back_jumps
from r2morph.mutations.code_virtualization_engine import (
    GP_REGISTERS,
    RSP_INDEX,
    gp_save_order,
)
from r2morph.mutations.code_virtualization_region_codegen_encode import (
    _item_size,
    build_ijmp_targets,
    encode_region,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import (
    avx128_upper_clear_asm,
    xmm_reload_asm,
    xmm_spill_asm,
)
from r2morph.mutations.code_virtualization_region_handler_codegen import handler_instances_asm
from r2morph.mutations.code_virtualization_region_handler_router import HandlerContext
from r2morph.mutations.code_virtualization_region_handlers import (
    _GUARD,
    _KEY_DWORD_SLOT,
    _KEY_QWORD_SLOT,
    _VSP_OFFSET,
    frame_size_for_seed,
)
from r2morph.mutations.code_virtualization_region_integrity import (
    ChecksumPrologue,
    checksum_prologue_asm,
    compute_build_checksum,
)
from r2morph.mutations.code_virtualization_region_models import (
    _DWORD_BROADCAST,
    Region,
    RegionScheme,
)
from r2morph.mutations.code_virtualization_region_regcipher import cipher_register_slots

logger = logging.getLogger(__name__)

_XMM_CALL_KINDS = frozenset({"call", "icall", "callmem", "callmemrip", "callmemidx", "vcall"})


def _interpreter_asm(region: Region, scheme: RegionScheme) -> str:
    # The operand cipher key is the runtime self-checksum, not a build constant: the
    # byte key is the checksum slot read directly, and the 32/64-bit keys are its
    # broadcasts, precomputed into frame slots at entry (see the setup below). Every
    # handler decrypts operands against these, so no operand-cipher literal is exposed.
    key = f"byte ptr [rsp+{scheme.checksum_offset}]"
    key_qword = f"qword ptr [rsp+{_KEY_QWORD_SLOT}]"
    key_dword = f"dword ptr [rsp+{_KEY_DWORD_SLOT}]"
    retarget_target = (
        f"  mov eax, dword ptr [rsi+1]\n  xor eax, {key_dword}\n"
        # Un-mask the position the encoder folded into the target (r13b holds it
        # from the dispatch), broadcast to 32 bits - the branch offset is keyed by
        # key XOR position like every other operand.
        f"  movzx r10d, r13b\n  imul r10d, r10d, {hex(_DWORD_BROADCAST)}\n  xor eax, r10d\n"
        "  lea r9, [rip+bytecode]\n  add r9, rax\n"
    )
    # The unconditional jmp handler commits the decoded target straight to the vIP;
    # the conditional handler selects between it and the fall-through branch-free.
    retarget = retarget_target + "  mov rsi, r9\n  jmp vm_dispatch\n"

    slot = scheme.slot_perm  # logical register index -> shuffled frame slot
    save_order = gp_save_order(scheme.junk_seed ^ 0x51A7E)
    frame_size = frame_size_for_seed(scheme.junk_seed)
    rsp_off = slot[RSP_INDEX] * 8  # byte offset of the relocated program rsp slot
    # Preserve XMM state for every FP operation and every native-call bridge. Calls
    # need the saved vector arguments and must write back caller-clobbered results.
    has_fp = any(
        item[0].startswith("fp") or item[0] in ("cvti2f", "cvtf2i", *_XMM_CALL_KINDS) for item in region.instructions
    )
    # Zero the virtual operand stack pointer; micro-op arithmetic folds through it.
    lines = [f"vm_entry:\n  sub rsp, {frame_size}\n  mov qword ptr [rsp+{_VSP_OFFSET}], 0\n"]
    for index in save_order:
        lines.append(f"  mov qword ptr [rsp+{slot[index] * 8}], {GP_REGISTERS[index]}\n")
    if has_fp:
        lines.append(xmm_spill_asm())
    # Anti-tamper: checksum the interpreter's own code into a frame slot the
    # dispatch folds into every opcode decrypt. Runs after the spill, so the
    # scratch registers it clobbers are already saved. The trailing offset table
    # (encrypted after assembly) is excluded from the checksummed span.
    lines.append(
        checksum_prologue_asm(
            ChecksumPrologue(
                scheme.xor_key,
                end_label="vm_bootstrap",
                slot=scheme.checksum_offset,
                bytewise=scheme.checksum_bytewise,
                label_prefix="entry_",
                reverse=scheme.checksum_reverse,
            )
        )
    )
    # Direct-threaded, polymorphic dispatch: rather than a single shared dispatch
    # block every handler jumps back to (a fan-in hub a devirtualizer flags as the
    # dispatcher by in-degree, and pattern-matches as one fixed sequence), the
    # opcode decode is inlined at the entry and at the tail of every handler, and
    # each copy shuffles its order-independent XOR groups so no two copies share a
    # byte layout. Each handler thus decodes the next opcode itself and jumps
    # straight to the next handler. The decode runs once per opcode either way and
    # shuffling only reorders instructions, so executed count and size are
    # unchanged; only the interpreter's code grows (one copy per handler).
    poly_rng = random.Random(scheme.table_key)
    table_mix = (scheme.table_key & 0x7FFFFFFF) | 1
    handler_count = sum(len(indices) for indices in scheme.dup.values())
    # Undo the opcode byte's position mask and the runtime self-checksum the whole-blob
    # pass XORed in: a faithful interpreter cancels the checksum and a tampered one
    # misdecodes every opcode. There is no separate constant key term -- the byte key
    # IS the checksum -- so the opcode decrypt exposes no operand-cipher literal.
    opcode_xors = [
        "  xor al, r13b\n",
        f"  xor al, byte ptr [rsp+{scheme.checksum_offset}]\n",
    ]
    bounds = f"  cmp al, {handler_count}\n  jae vm_exit\n"
    state_key = f"qword ptr [rsp+{scheme.state_offset}]"
    state_decode = f"  xor rsi, {state_key}\n" f"  xor r15, {state_key}\n" f"  xor r13, {state_key}\n"

    def make_decode() -> str:
        return decode_block(
            opcode_xors=opcode_xors,
            bounds=bounds,
            # Base-independent indirect dispatch: each table entry is a 32-bit signed
            # offset from vm_table to its handler. The offsets use a checksum key mixed
            # with the opcode index and a per-build multiplier.
            table_load=(
                "  lea r14, [rip+vm_table]\n" "  mov edx, eax\n" "  inc edx\n" "  mov eax, dword ptr [r14+rax*4]\n"
            ),
            table_xors=[
                (
                    f"  movzx ecx, byte ptr [rsp+{scheme.checksum_offset}]\n"
                    f"  imul ecx, ecx, 0x1010101\n"
                    f"  imul edx, edx, {table_mix}\n"
                    f"  xor ecx, edx\n  xor eax, ecx\n{state_decode}"
                ),
            ],
            rng=poly_rng,
        )

    # Capture the program's entry rsp, then relocate its virtual stack a guard
    # distance below the VM frame so the function's own push/pop never collides with
    # the spilled context. rsp is only ever a memory base or a push/pop target, so
    # this constant shift stays self-consistent. r13/r14 are free scratch between
    # handlers; r15 holds the bytecode base.
    has_in_function_call = any(item[0] == "vcall" for item in region.instructions)
    # A region with an in-function call reserves one floor cell below the relocated
    # program stack and zeroes it: a vret that unwinds to the outermost frame finds
    # this non-bytecode value on top (no vcall resume is pending there) and returns
    # natively, instead of reading uninitialized memory that might alias the bytecode
    # range. rax is free scratch here (every GP register was already spilled).
    floor_cell = "  sub rax, 8\n  mov qword ptr [rax], 0\n" if has_in_function_call else ""
    entry_setup = (
        f"  lea rax, [rsp+{frame_size}]\n  sub rax, {_GUARD}\n{floor_cell}"
        f"  xor rax, qword ptr [rsp+{_KEY_QWORD_SLOT}]\n  mov qword ptr [rsp+{slot[RSP_INDEX] * 8}], rax\n"
        "  lea rsi, [rip+bytecode]\n  mov r15, rsi\n"
    )
    key_setup = (
        checksum_prologue_asm(
            ChecksumPrologue(
                scheme.xor_key,
                slot=scheme.checksum_offset,
                bytewise=scheme.checksum_bytewise,
                label_prefix="ready_",
                reverse=scheme.checksum_reverse,
            )
        )
        + f"  movzx eax, byte ptr [rsp+{scheme.checksum_offset}]\n"
        "  imul eax, eax, 0x1010101\n"
        f"  mov dword ptr [rsp+{_KEY_DWORD_SLOT}], eax\n"
        f"  movzx rax, byte ptr [rsp+{scheme.checksum_offset}]\n"
        "  mov rcx, 0x0101010101010101\n"
        "  imul rax, rcx\n"
        f"  mov qword ptr [rsp+{_KEY_QWORD_SLOT}], rax\n"
        f"  lea rax, [rsp+{frame_size}]\n"
        "  ror rax, 17\n"
        f"  xor rax, qword ptr [rsp+{_KEY_QWORD_SLOT}]\n"
        f"  mov qword ptr [rsp+{scheme.state_offset}], rax\n"
    )
    encrypt_slots = "".join(
        f"  mov rax, qword ptr [rsp+{slot[index] * 8}]\n"
        f"  xor rax, qword ptr [rsp+{_KEY_QWORD_SLOT}]\n"
        f"  mov qword ptr [rsp+{slot[index] * 8}], rax\n"
        for index in save_order
    )
    bootstrap, bootstrap_table = build_bootstrap_asm(
        scheme.checksum_offset,
        scheme.junk_seed,
        key_setup + encrypt_slots + entry_setup + make_decode(),
    )
    lines.append(f"vm_bootstrap:\n{bootstrap}")

    reload_seq = "".join(f"  mov {GP_REGISTERS[index]}, qword ptr [rsp+{slot[index] * 8}]\n" for index in save_order)
    if has_fp:
        reload_seq += xmm_reload_asm()
        vex_destinations = {int(item[2]) for item in region.instructions if item[0] in ("fppackedvex", "fpmovvex")}
        reload_seq += avx128_upper_clear_asm(vex_destinations)

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
    # Encrypt the register file: cipher every GP-slot load/store in the handler bodies
    # (the reload sequence and the relocated-rsp accesses ride along, being slot
    # offsets below the array end) so the context is stored XOR'd with the checksum key.
    lines.append(
        cipher_register_slots(
            handler_instances_asm(
                index_to_key,
                HandlerContext(
                    key,
                    key_qword,
                    key_dword,
                    rsp_off,
                    reload_seq,
                    retarget,
                    retarget_target,
                    frame_size,
                    slot,
                    sum(_item_size(item) for item in region.instructions),
                    scheme.field_perm,
                    scheme.body_seed,
                    scheme.isa_seed,
                    scheme.flags_offset,
                ),
                junk_rng,
                entry_prefix=state_decode,
            ),
            frozenset(index * 8 for index in slot),
        )
    )

    # Every index in 0..total-1 maps to a handler; the bounds guard above sends an
    # out-of-range (corrupt) opcode to the default exit so it cannot leave the VM.
    table = "".join(f"  .long H_{index} - vm_table\n" for index in range(total))
    # Runtime target map for computed jumps (ijmp): a count followed by (map-relative
    # target delta, bytecode offset) pairs the ijmp handler scans to re-enter the VM
    # at a virtualized target. Empty for an ordinary region, so its blob is unchanged.
    # It is emitted BEFORE vm_table so build_region_blob can locate the main and
    # bootstrap tables as the fixed-size suffix before the tracer island.
    #
    # Each key is the link-time delta ``ijmp_map - target`` instead of the target
    # address itself, so the map holds no absolute address and the scan matches at
    # any load base (the handler normalizes the runtime target the same way; see
    # _ijmp_scan_asm). The subtrahend order matters: the assembler resolves
    # ``label - constant`` but not ``constant - label``, and the handler cancels
    # the sign by computing map minus target too. The bytecode offset stays a
    # plain ``.long`` - it is already relative to the bytecode label.
    ijmp_targets = build_ijmp_targets(region)
    ijmp_map = ""
    if ijmp_targets:
        entries = "".join(f"  .quad ijmp_map - {addr}\n  .long {offset}\n" for addr, offset in ijmp_targets)
        ijmp_map = f"ijmp_map:\n  .long {len(ijmp_targets)}\n{entries}"
    # The bootstrap table and tracer-constant island trail the main dispatch table,
    # outside the checksummed span and before the appended bytecode.
    lines.append(
        f"vm_exit:\n{reload_seq}  add rsp, {frame_size}\n  jmp {hex(region.exit_vaddr)}\n"
        f"{ijmp_map}vm_table:\n{table}{bootstrap_table}{tracer_const_island_asm()}bytecode:\n"
    )
    # Thread the dispatch: every handler tail (and the retarget) ends with a back
    # jump to the (now removed) central dispatcher; splice a freshly shuffled
    # decode copy in for each so control flows handler -> decode -> next handler
    # with no shared hub block and no two copies sharing a byte layout.
    interpreter = thread_back_jumps("".join(lines), make_decode)
    # Relocate the flags slot: every flag capture/restore and the branch-free jcc's
    # flags read renders as the memory operand `[rsp + 128]` (the canonical 0x80
    # slot). GP outliers use 0x90/0xA8, the checksum never uses 0x80, and the xmm
    # area is indexed (`[rsp + r8 + ...]`), so this rewrites exactly the flag
    # references without threading the offset through every handler.
    return re.sub(r"\[rsp\s*\+\s*128\]", f"[rsp + {scheme.flags_offset}]", interpreter)


def build_region_blob(region: Region, cave_vaddr: int, scheme: RegionScheme) -> bytes | None:
    """Assemble the region interpreter at ``cave_vaddr`` and append its bytecode."""
    try:
        keystone = import_module("keystone")
    except ImportError:
        logger.warning("keystone unavailable; cannot virtualize region")
        return None
    try:
        engine = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        asm = _interpreter_asm(region, scheme)
        encoding, _ = engine.asm(asm, cave_vaddr)
    except keystone.KsError as exc:
        logger.debug("Region interpreter assembly failed: %s", exc)
        return None
    if not encoding:
        return None
    data = bytearray(encoding)
    total = sum(len(indices) for indices in scheme.dup.values())
    # The assembled interpreter ends with the main and bootstrap offset tables,
    # followed by the tracer-constant island; all trail vm_table and are excluded
    # from the checksummed span. XOR-encrypt each table entry in place so
    # the handler addresses are not a plaintext jump table (the dispatch decrypts
    # them at runtime with the same key, and keystone cannot XOR a label difference
    # it computes itself, so the encryption happens here on the assembled bytes).
    island_start = len(data) - _TRACER_ISLAND_LEN
    bootstrap_start = island_start - BOOTSTRAP_TABLE_SIZE
    table_start = bootstrap_start - total * 4
    bootstrap_checksum = compute_build_checksum(
        bytes(engine.asm(asm[: asm.index("vm_bootstrap:") + len("vm_bootstrap:")], cave_vaddr)[0]),
        scheme.xor_key,
        scheme.checksum_bytewise,
        scheme.checksum_reverse,
    )
    # Expected runtime self-checksum over the interpreter code (everything up to the
    # dispatch table, so neither the table encryption nor the island patch below
    # perturbs it); the encoder folds it into the opcodes, the table is encrypted
    # with it, and the tracer constants are masked by it. The table key also includes
    # a build-derived index mix, so entries do not share one uniform XOR mask.
    checksum = compute_build_checksum(
        bytes(data[:table_start]), scheme.xor_key, scheme.checksum_bytewise, scheme.checksum_reverse
    )
    table_mix = (scheme.table_key & 0x7FFFFFFF) | 1
    for entry_index in range(total):
        offset = table_start + entry_index * 4
        entry_key = table_entry_key(checksum, entry_index, table_mix)
        encrypted = int.from_bytes(data[offset : offset + 4], "little") ^ entry_key
        data[offset : offset + 4] = encrypted.to_bytes(4, "little")
    encrypt_bootstrap_table(data, bootstrap_start, bootstrap_checksum, table_key_mix(scheme.junk_seed))
    patch_tracer_constants(data, island_start, bootstrap_checksum)
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
