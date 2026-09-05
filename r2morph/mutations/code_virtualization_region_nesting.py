"""Nested (multi-layer) region virtualization.

A single virtualized region is one interpreter an analyst peels in one pass.
This module wraps a region in a second VM layer: a contiguous run of plain
register operations is *peeled* out of the outer bytecode into an inner stream
that a second, independently-keyed interpreter executes, reached through an
``enter_inner`` transfer opcode and returning through ``inner_exit``. The two
layers share one register frame (so the peeled run has the same effect it would
have had inline) but have their own opcode permutation and dispatch table - so
recovering the outer VM only reveals a second VM to peel. The opcode/operand
cipher key and the dispatch-table key are the shared runtime self-checksum, while
the live-state mask is kept in a separate stack-derived slot, so neither state nor
operand decoding depends on a build-constant mask.

One shared, slot-driven dispatcher serves both layers: the transfer handlers
write the active layer's handler count and dispatch-table base into frame slots,
so every existing handler builder is reused verbatim (each decrypts its operands
against the shared checksum and jumps to the one ``vm_dispatch``). Only
flag-independent register-op runs are peeled, so no branch target ever crosses
the layer boundary.

The runtime self-checksum (:mod:`code_virtualization_region_integrity`) spans
both layers' code, so tampering with either layer diverges both.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from importlib import import_module
from typing import Any

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
    table_key_mix,
)
from r2morph.mutations.code_virtualization_dispatch import decode_block, thread_back_jumps
from r2morph.mutations.code_virtualization_engine import GP_REGISTERS, RSP_INDEX, gp_save_order
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen_encode import (
    _item_size,
    encode_region,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import (
    avx128_upper_clear_asm,
    xmm_reload_asm,
    xmm_spill_asm,
    ymm_upper_reload_asm,
    ymm_upper_spill_asm,
)
from r2morph.mutations.code_virtualization_region_handler_codegen import handler_instances_asm
from r2morph.mutations.code_virtualization_region_handler_router import HandlerContext
from r2morph.mutations.code_virtualization_region_handlers import (
    _KEY_DWORD_SLOT,
    _KEY_QWORD_SLOT,
    _STACK_ARGUMENT_COPY_BYTES,
    _VSP_OFFSET,
    frame_size_for_seed,
    stack_argument_copy_asm,
    stack_guard_for_copy,
)
from r2morph.mutations.code_virtualization_region_integrity import (
    _CHECKSUM_OFFSET,
    ChecksumPrologue,
    checksum_prologue_asm,
    compute_build_checksum,
)
from r2morph.mutations.code_virtualization_region_models import (
    _DWORD_BROADCAST,
    Region,
    RegionScheme,
    _op_key,
)
from r2morph.mutations.code_virtualization_region_regcipher import cipher_register_slots

logger = logging.getLogger(__name__)
_VEX_LOAD_KINDS = frozenset({"fploadvex", "fploadvexrip", "fploadvexidx", "fploadvexidxnb"})

# Frame slots above the checksum byte (0x88) and below the preserved red zone
# (0x100): the dispatcher reads the active layer's parameters from these, the
# transfer handlers write them. Each parent->child transition gets its own
# return-pointer slot at _RETURN_BASE + index*8, so a chain of nested layers
# returns correctly without a runtime stack.
_COUNT_OFFSET = 0x98  # active layer handler count (byte)
_TABLE_OFFSET = 0xA0  # active layer dispatch-table base (absolute addr)
_RETURN_BASE = 0xB0  # first parent-bytecode-pointer return slot

_MIN_PEEL = 2  # shortest op run worth peeling into an inner layer
# Cap layers so the per-transition return slots stay below the red zone (0x100).
_MAX_LAYERS = (0x100 - _RETURN_BASE) // 8
_XMM_CALL_KINDS = frozenset({"call", "icall", "callmem", "callmemrip", "callmemidx", "callmemidxnb", "vcall"})


def _stack_copy_bytes(region: Region) -> int:
    return max(_STACK_ARGUMENT_COPY_BYTES, region.stack_argument_copy_bytes)


def _region_stack_guard(region: Region, junk_seed: int) -> int:
    return stack_guard_for_copy(frame_size_for_seed(junk_seed), _stack_copy_bytes(region))


@dataclass(frozen=True)
class _NestedEncodingContext:
    layers: list[Region]
    schemes: list[RegionScheme]
    counts: list[int]
    offsets: list[int]
    lengths: list[int]
    cave_vaddr: int
    bootstrap_checksum: int


def _branch_targets(instructions: list[tuple[Any, ...]]) -> set[int]:
    """Item indices some control-transfer item resolves to.

    ``vcall`` carries its callee's item index in the same field a ``jmp`` does, so
    it names a target exactly like a branch and belongs in this set.
    """
    targets: set[int] = set()
    for item in instructions:
        if item[0] in ("jmp", "vcall"):
            targets.add(item[1])
        elif item[0] == "jcc":
            targets.add(item[2])
    return targets


def _peel_op_run(instructions: list[tuple[Any, ...]]) -> tuple[int, int] | None:
    """Find the longest contiguous register-op run safe to move to an inner layer.

    Only ``op``/``opmba``/``opsynth`` items are eligible (pure register/immediate
    arithmetic, no memory, stack or control flow). ``opsynth`` writes the shared
    flags slot, which the layer-transfer handlers leave untouched, so the outer
    layer's later branch still reads the flags the peeled op produced. The run's
    first item may be a target (a transfer to it becomes a transfer to the
    ``enter_inner`` that runs the whole run), but no interior item may be, so no
    branch or in-function call ever lands mid-run.
    """
    eligible = (
        "op",
        "opmba",
        "opsynth",
        "vpush",
        "vpop",
        "vpop8",
        "vpop16",
        "vpushi",
        "vbinop",
        "vbinopsynth",
        "vsuper",
        "vload",
        "vstore",
        "vloadidx",
        "vstoreidx",
        "vloadidxnb",
        "vstoreidxnb",
        "vloadrip",
        "vstorerip",
        "vlea",
        "vlearip",
        "vleaidx",
        "vleaidxnb",
        "vmovx",
        "vmovxidx",
        "vmovxidxnb",
        "vshift",
        "vshiftreg",
        "vcmpsynth",
    )
    targets = _branch_targets(instructions)

    best: tuple[int, int] | None = None
    i = 0
    n = len(instructions)
    while i < n:
        if instructions[i][0] in eligible:
            j = i + 1
            while j < n and instructions[j][0] in eligible and j not in targets:
                j += 1
            if j - i >= _MIN_PEEL and (best is None or (j - i) > (best[1] - best[0])):
                best = (i, j)
            i = j
        else:
            i += 1
    return best


def split_region(region: Region, rng: random.Random) -> tuple[Region, Region] | None:
    """Split ``region`` into an outer region (with an ``enter_inner`` marker) and
    an inner region (the peeled run plus an ``inner_exit`` terminator).

    Returns ``None`` when the region cannot be split faithfully, so the caller
    falls back to a single-layer build.
    """
    if region.target_map:
        # A computed-jump target map indexes this region's item list, and the split
        # renumbers those items; neither region built below carries a map, so a
        # mapped region would silently lose its runtime re-entry points.
        return None
    run = _peel_op_run(region.instructions)
    if run is None:
        return None
    start, end = run
    if any(start < target < end for target in _branch_targets(region.instructions)):
        # A target strictly inside the collapsed run has no outer item left to name;
        # remapping it would produce an index outside the outer stream.
        return None
    instrs = list(region.instructions)
    shift = (end - start) - 1  # items removed from the outer stream

    def remap(target: int) -> int:
        if target <= start:
            return target  # before, or the run head (now the enter_inner item)
        return target - shift  # after the collapsed run

    outer_items: list[tuple[Any, ...]] = []
    for idx, item in enumerate(instrs):
        if start <= idx < end:
            if idx == start:
                outer_items.append(("enter_inner",))
            continue
        if item[0] == "jmp":
            outer_items.append(("jmp", remap(item[1])))
        elif item[0] == "vcall":
            outer_items.append(("vcall", remap(item[1])))
        elif item[0] == "jcc":
            outer_items.append(("jcc", item[1], remap(item[2])))
        else:
            outer_items.append(item)
    inner_items: list[tuple[Any, ...]] = [*instrs[start:end], ("inner_exit",)]

    outer = Region(
        outer_items,
        region.exit_vaddr,
        region.entry_vaddr,
        {k for it in outer_items if (k := _op_key(it)) is not None},
        region.body_ranges,
        stack_argument_copy_bytes=region.stack_argument_copy_bytes,
    )
    inner = Region(
        inner_items,
        region.exit_vaddr,
        region.entry_vaddr,
        {k for it in inner_items if (k := _op_key(it)) is not None},
        [],
        stack_argument_copy_bytes=region.stack_argument_copy_bytes,
    )
    return outer, inner


def _relayer_sharing_frame(schemes: list[RegionScheme], slot: tuple[int, ...]) -> list[RegionScheme]:
    """Rebuild each layer's scheme so all layers share the frame layout but each
    keeps its own handler personality.

    Only ``slot`` (the register->frame-slot permutation) is forced shared: every
    layer must read and write the same physical frame slot for a given logical
    register, and the nested path drives the checksum/flags slots from module
    constants rather than per-scheme offsets, so the shared frame stays consistent
    across the ``enter_inner``/``inner_exit`` transfers. Each layer keeps its own
    ``body_seed`` (per-handler scratch rename) and ``isa_seed`` (flag/arith/compare/
    shift/address fold spelling): these are layer-local semantic choices, and the
    flag bits a handler stores are correct for any ``isa_seed`` (the ISA equivalence
    tests pin this), so distinct per-layer personalities never corrupt the shared
    flags slot the layers transfer through. Preserving them lets the default (nested)
    build regain the ISA-personality and scratch-rename diversity a single-layer
    build has, and gives inner layers algebra distinct from the outer layer's.
    """
    return [
        RegionScheme(
            s.dup,
            s.xor_key,
            s.junk_seed,
            slot,
            s.table_key,
            s.field_perm,
            body_seed=s.body_seed,
            isa_seed=s.isa_seed,
            checksum_bytewise=s.checksum_bytewise,
            state_offset=schemes[0].state_offset,
            checksum_reverse=s.checksum_reverse,
            dispatch_variant=s.dispatch_variant,
        )
        for s in schemes
    ]


def _scheme_count(scheme: RegionScheme) -> int:
    return sum(len(indices) for indices in scheme.dup.values())


def _index_to_key(scheme: RegionScheme, offset: int = 0) -> dict[int, str]:
    return {offset + index: key for key, indices in scheme.dup.items() for index in indices}


def _set_layer_slots(layer: int, count: int) -> str:
    """Assembly that points the shared decode at one layer's parameters.

    Writes this layer's handler count and dispatch-table base so the inlined decode
    copies resolve the active layer's handlers. The opcode/operand cipher key is the
    shared self-checksum (not per layer), so no per-layer key slot is written.
    """
    return (
        f"  mov byte ptr [rsp+{_COUNT_OFFSET}], {count}\n"
        + f"  lea rax, [rip+vm_table_{layer}]\n"
        + f"  mov qword ptr [rsp+{_TABLE_OFFSET}], rax\n"
    )


def _nested_xmm_state_asm(region: Region, layers: list[Region]) -> tuple[str, str]:
    """Preserve vector state for nested regions and native-call bridges."""
    has_fp = any(
        item[0].startswith("fp") or item[0] in ("cvti2f", "cvtf2i", "vzeroupper", "vzeroall", *_XMM_CALL_KINDS)
        for item in region.instructions
    )
    if not has_fp:
        return "", ""
    has_ymm = any(
        item[0]
        in (
            "fparithvex",
            "fparithvexmem",
            "fparithvexmemrip",
            "fparithvexmemidx",
            "fparithvexmemidxnb",
            "fppackedvex",
            "fppackedveximm",
            "fpmovvex",
            "fpmovvexscalar",
            "fpmovvexscalar3",
            "fpmovvexgp",
            "fpmovvexgpd",
            "fpmovmskbvex256",
            "fpcmpvex256",
            "fppackedvex256cmp",
            "fppackedvex256cmpmem",
            "fppackedvex256cmpmemrip",
            "fppackedvex256cmpmemidx",
            "fppackedvex256cmpmemidxnb",
            "fploadvex",
            "fploadvexrip",
            "fploadvexidx",
            "fploadvexidxnb",
            "fpmovvexmem",
            "fpmovvexmemrip",
            "fpmovvexmemidx",
            "fpmovvexmemidxnb",
            "fppackedvex256",
            "fppackedvex256imm",
            "fppackedvex256var",
            "fppackedvex256varpermil",
            "fppackedvex256permimm",
            "fppackedvex256permilimm",
            "fppackedvex256mem",
            "fppackedvex256memrip",
            "fppackedvex256memidx",
            "fppackedvex256memidxnb",
            "fppackedvexmem",
            "fppackedvexmemrip",
            "fppackedvexmemidx",
            "fppackedvexmemidxnb",
            "fpmovvex256",
            "vzeroupper",
            "vzeroall",
        )
        for layer in layers
        for item in layer.instructions
    )
    vex_destinations = {
        int(item[1] if item[0] in _VEX_LOAD_KINDS else item[2])
        for layer in layers
        for item in layer.instructions
        if item[0]
        in (
            "fparithvex",
            "fparithvexmem",
            "fparithvexmemrip",
            "fparithvexmemidx",
            "fparithvexmemidxnb",
            "fppackedvex",
            "fppackedvexcmp",
            "fppackedvexcmpmem",
            "fppackedvexcmpmemrip",
            "fppackedvexcmpmemidx",
            "fppackedvexcmpmemidxnb",
            "fppackedveximm",
            "fppackedvexmem",
            "fppackedvexmemrip",
            "fppackedvexmemidx",
            "fppackedvexmemidxnb",
            "fpmovvex",
            "fpmovvexscalar",
            "fpmovvexscalar3",
            "fpmovvexgp",
            "fpmovvexgpd",
            "fploadvex",
            "fploadvexrip",
            "fploadvexidx",
            "fploadvexidxnb",
            "fpmovvexmem",
            "fpmovvexmemrip",
            "fpmovvexmemidx",
            "fpmovvexmemidxnb",
        )
    }
    spill = xmm_spill_asm()
    reload = xmm_reload_asm() + avx128_upper_clear_asm(vex_destinations)
    if has_ymm:
        spill += ymm_upper_spill_asm()
        reload += ymm_upper_reload_asm()
    return spill, reload


def _enter_inner_asm(child: int, child_count: int, return_slot: int) -> str:
    """Handler that saves the resume point and transfers down to layer ``child``."""
    return (
        f"  lea rax, [rsi+1]\n  mov qword ptr [rsp+{return_slot}], rax\n"
        + _set_layer_slots(child, child_count)
        + f"  lea rsi, [rip+bc_{child}]\n  mov r15, rsi\n  jmp vm_dispatch\n"
    )


def _inner_exit_asm(parent: int, parent_count: int, return_slot: int) -> str:
    """Handler that restores the parent layer's parameters and resumes it."""
    return (
        _set_layer_slots(parent, parent_count)
        + f"  mov rsi, qword ptr [rsp+{return_slot}]\n  lea r15, [rip+bc_{parent}]\n  jmp vm_dispatch\n"
    )


def _decode_block(rng: random.Random, state_offset: int = 0x218) -> str:
    # Direct-threaded, polymorphic decode block (no label): the opcode is decoded
    # with the active layer's key (frame slot) plus the position mask and self-
    # checksum, bounds-checked against the active handler count, then dispatched
    # through the active table. This body is inlined at the entry and at the tail
    # of every handler and transfer stub, so there is no single shared dispatcher
    # node for a devirtualizer to find by in-degree; control threads handler ->
    # decode -> next handler. Each copy shuffles its order-independent XOR groups,
    # so no two share a byte layout. It runs once per opcode either way and
    # shuffling only reorders instructions, so executed count and size are
    # unchanged; only interpreter code size grows (scanned once).
    return decode_block(
        opcode_xors=[
            "  xor al, r13b\n",
            f"  xor al, byte ptr [rsp+{_CHECKSUM_OFFSET}]\n",
        ],
        bounds=f"  movzx ecx, byte ptr [rsp+{_COUNT_OFFSET}]\n  cmp al, cl\n  jae vm_exit\n",
        table_load=f"  mov r14, qword ptr [rsp+{_TABLE_OFFSET}]\n  mov eax, dword ptr [r14+rax*4]\n",
        # Encrypt the table with the self-checksum broadcast to 32 bits -- a value the
        # decompiler cannot fold, so the decrypt exposes no per-layer table-key literal
        # -- and tampering corrupts handler resolution in every layer. One checksum
        # covers the whole nested blob, so every layer's table shares this key.
        table_xors=[
            (
                f"  movzx ecx, byte ptr [rsp+{_CHECKSUM_OFFSET}]\n"
                f"  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n"
                f"  xor rsi, qword ptr [rsp+{state_offset}]\n"
                f"  xor r15, qword ptr [rsp+{state_offset}]\n"
                f"  xor r13, qword ptr [rsp+{state_offset}]\n"
            ),
        ],
        rng=rng,
    )


def _build_layers(region: Region, depth: int, rng: random.Random) -> list[Region] | None:
    """Recursively peel an op run out of each layer to form a chain of regions.

    Layer 0 is the outermost (entered natively); each later layer is entered from
    its parent and returns to it. Stops at ``depth`` layers or when no further run
    is peelable. Returns ``None`` if nothing peeled (use the single-layer blob).
    """
    if any(item[0].startswith("fp") or item[0] in ("cvti2f", "cvtf2i") for item in region.instructions):
        return None
    layers: list[Region] = []
    current = region
    while len(layers) < depth - 1:
        split = split_region(current, rng)
        if split is None:
            break
        parent, child = split
        layers.append(parent)
        current = child
    if not layers:
        return None
    layers.append(current)
    return layers


def _finalize_nested_blob(encoding: list[int], context: _NestedEncodingContext) -> bytes | None:
    count = len(context.layers)
    data = bytearray(encoding)
    bytecode_offsets = [0] * count
    bytecode_offsets[-1] = len(data)
    for layer in range(count - 2, -1, -1):
        bytecode_offsets[layer] = bytecode_offsets[layer + 1] - context.lengths[layer]

    island_start = bytecode_offsets[0] - _TRACER_ISLAND_LEN
    bootstrap_start = island_start - BOOTSTRAP_TABLE_SIZE
    table_start = bootstrap_start - sum(context.counts) * 4
    checksum = compute_build_checksum(
        bytes(data[:table_start]),
        context.schemes[0].xor_key,
        context.schemes[0].checksum_bytewise,
        context.schemes[0].checksum_reverse,
    )
    logger.warning("Nested VM checksum diagnostic: value=%02x", checksum)
    checksum_broadcast = checksum * 0x01010101
    for layer in range(count):
        _encrypt_table(
            data,
            table_start + context.offsets[layer] * 4,
            context.counts[layer],
            checksum_broadcast,
        )
    encrypt_bootstrap_table(
        data,
        bootstrap_start,
        context.bootstrap_checksum,
        table_key_mix(context.schemes[0].junk_seed),
    )
    patch_tracer_constants(data, island_start, context.bootstrap_checksum)
    try:
        encoded_layers = [
            encode_region(
                context.layers[layer],
                context.schemes[layer],
                context.cave_vaddr + bytecode_offsets[layer],
                checksum,
            )
            for layer in range(count)
        ]
    except struct.error:
        logger.debug("rip-relative target out of 32-bit range; cannot nest")
        return None
    for layer in range(count - 1):
        start = bytecode_offsets[layer]
        data[start : start + context.lengths[layer]] = encoded_layers[layer]
    return bytes(data) + encoded_layers[-1]


def build_nested_region_blob(region: Region, cave_vaddr: int, rng: random.Random, depth: int = 2) -> bytes | None:
    """Assemble an N-layer nested interpreter for ``region`` at ``cave_vaddr``.

    Each layer is an independently-keyed VM; a peeled register-op run in layer
    ``k`` runs in layer ``k+1``, reached by ``enter_inner`` and returning through
    ``inner_exit``. Returns ``None`` if the region has no peelable run or assembly
    fails, so the caller can fall back to the single-layer blob.
    """
    try:
        keystone = import_module("keystone")
    except ImportError:
        logger.warning("keystone unavailable; cannot nest region virtualization")
        return None

    # Calls never enter the peeled inner run (they are not in _peel_op_run's eligible
    # set), so every call kind stays in the outer layer where r15 is that layer's
    # bytecode base bc_0 - exactly the base the direct-call target and the vcall/vret
    # resume discriminator are keyed to. The threaded bytecode_len (per layer) and the
    # floor cell below carry the in-function-call return discipline into the nested
    # build, so a call-bearing region nests instead of falling back to single-layer.
    layers = _build_layers(region, max(2, min(depth, _MAX_LAYERS)), rng)
    if layers is None:
        return None
    # Build a scheme per layer; all share the outermost slot permutation so every
    # layer reads and writes the same frame slots for a given logical register.
    schemes = [build_region_scheme(layer, rng) for layer in layers]
    slot = schemes[0].slot_perm
    schemes = _relayer_sharing_frame(schemes, slot)
    counts = [_scheme_count(s) for s in schemes]
    offsets = [sum(counts[:i]) for i in range(len(layers))]  # global handler-index base per layer
    rsp_off = slot[RSP_INDEX] * 8
    xmm_state = _nested_xmm_state_asm(region, layers)
    spill = (
        "".join(
            f"  mov qword ptr [rsp+{slot[index] * 8}], {GP_REGISTERS[index]}\n"
            for index in gp_save_order(schemes[0].junk_seed ^ 0x51A7E)
        )
        + xmm_state[0]
    )
    reload_seq = (
        "".join(
            f"  mov {GP_REGISTERS[index]}, qword ptr [rsp+{slot[index] * 8}]\n"
            for index in gp_save_order(schemes[0].junk_seed ^ 0x51A7E)
        )
        + xmm_state[1]
    )

    # An in-function call (vcall, always in the outer layer) reserves a zeroed floor
    # cell below the relocated program stack so a ret unwinding to the outermost frame
    # reads a non-bytecode value and returns natively - see the single-layer builder.
    has_in_function_call = any(item[0] == "vcall" for item in region.instructions)
    floor_cell = "  sub rax, 8\n  mov qword ptr [rax], 0\n" if has_in_function_call else ""

    ready = (
        checksum_prologue_asm(
            ChecksumPrologue(
                schemes[0].xor_key,
                end_label="vm_table_0",
                slot=_CHECKSUM_OFFSET,
                bytewise=schemes[0].checksum_bytewise,
                label_prefix="ready_",
                reverse=schemes[0].checksum_reverse,
            )
        )
        + f"  movzx eax, byte ptr [rsp+{_CHECKSUM_OFFSET}]\n  imul eax, eax, 0x1010101\n"
        + f"  mov dword ptr [rsp+{_KEY_DWORD_SLOT}], eax\n"
        + f"  movzx rax, byte ptr [rsp+{_CHECKSUM_OFFSET}]\n  mov rcx, 0x0101010101010101\n  imul rax, rcx\n"
        + f"  mov qword ptr [rsp+{_KEY_QWORD_SLOT}], rax\n"
        + f"  lea rax, [rsp+{frame_size_for_seed(schemes[0].junk_seed)}]\n"
        + "  ror rax, 17\n"
        + f"  xor rax, qword ptr [rsp+{_KEY_QWORD_SLOT}]\n"
        + f"  mov qword ptr [rsp+{schemes[0].state_offset}], rax\n"
        + "".join(
            f"  mov rax, qword ptr [rsp+{slot[i] * 8}]\n"
            f"  xor rax, qword ptr [rsp+{_KEY_QWORD_SLOT}]\n"
            f"  mov qword ptr [rsp+{slot[i] * 8}], rax\n"
            for i, name in enumerate(GP_REGISTERS)
            if name != "rsp"
        )
        + _set_layer_slots(0, counts[0])
        + stack_argument_copy_asm(
            frame_size_for_seed(schemes[0].junk_seed),
            _stack_copy_bytes(region),
            _region_stack_guard(region, schemes[0].junk_seed),
        )
        + f"  lea rax, [rsp+{frame_size_for_seed(schemes[0].junk_seed)}]\n"
        f"  sub rax, {_region_stack_guard(region, schemes[0].junk_seed)}\n{floor_cell}"
        + f"  xor rax, qword ptr [rsp+{_KEY_QWORD_SLOT}]\n  mov qword ptr [rsp+{rsp_off}], rax\n"
        + "  lea rsi, [rip+bc_0]\n  mov r15, rsi\n  jmp vm_dispatch\n"
    )
    bootstrap, bootstrap_table = build_bootstrap_asm(_CHECKSUM_OFFSET, schemes[0].junk_seed, ready)
    entry = (
        # Zero the virtual operand stack pointer before any micro-op runs; peeled
        # flag-dead arith folds through it in the nested layers too.
        f"vm_entry:\n  sub rsp, {frame_size_for_seed(schemes[0].junk_seed)}\n"
        f"  mov qword ptr [rsp+{_VSP_OFFSET}], 0\n{spill}"
        + checksum_prologue_asm(
            ChecksumPrologue(
                schemes[0].xor_key,
                end_label="vm_bootstrap",
                slot=_CHECKSUM_OFFSET,
                bytewise=schemes[0].checksum_bytewise,
                label_prefix="entry_",
                reverse=schemes[0].checksum_reverse,
            )
        )
        + f"vm_bootstrap:\n{bootstrap}"
    )

    # Shared junk stream so duplicate handlers across layers stay distinct.
    junk_seed = 0
    for scheme in schemes:
        junk_seed ^= scheme.junk_seed
    junk_rng = random.Random(junk_seed)

    # Each layer's bytecode byte length: the vret discriminator (only present in the
    # call-bearing outer layer) needs its own layer's length to range-check a resume
    # vIP against ``[r15, r15+len)``.
    lens = [sum(_item_size(item) for item in layer.instructions) for layer in layers]

    # One checksum covers the whole nested blob, so every layer's operand cipher key
    # is the same runtime self-checksum (byte read directly, 32/64-bit broadcasts from
    # the frame slots set once at entry) -- no build-constant key literal per layer.
    key = f"byte ptr [rsp+{_CHECKSUM_OFFSET}]"
    key_qword = f"qword ptr [rsp+{_KEY_QWORD_SLOT}]"
    key_dword = f"dword ptr [rsp+{_KEY_DWORD_SLOT}]"
    layer_bodies: list[str] = []
    for layer in range(len(layers)):
        scheme = schemes[layer]
        extra: dict[str, str] = {}
        if layer + 1 < len(layers):  # transfer down to the next layer
            extra["enter_inner"] = _enter_inner_asm(layer + 1, counts[layer + 1], _RETURN_BASE + layer * 8)
        if layer > 0:  # return up to the parent layer
            extra["inner_exit"] = _inner_exit_asm(layer - 1, counts[layer - 1], _RETURN_BASE + (layer - 1) * 8)
        retarget_target = (
            f"  mov eax, dword ptr [rsi+1]\n  xor eax, {key_dword}\n"
            # Un-mask the position the encoder folded into the branch target (r13b
            # holds it from the dispatch), broadcast to 32 bits - keyed by
            # key XOR position like every other operand in this layer's stream.
            f"  movzx r10d, r13b\n  imul r10d, r10d, {hex(_DWORD_BROADCAST)}\n  xor eax, r10d\n"
            f"  lea r9, [rip+bc_{layer}]\n  add r9, rax\n"
        )
        retarget = retarget_target + "  mov rsi, r9\n  jmp vm_dispatch\n"
        layer_bodies.append(
            cipher_register_slots(
                handler_instances_asm(
                    _index_to_key(scheme, offset=offsets[layer]),
                    HandlerContext(
                        key,
                        key_qword,
                        key_dword,
                        rsp_off,
                        reload_seq,
                        retarget,
                        retarget_target,
                        frame_size_for_seed(schemes[0].junk_seed),
                        slot,
                        lens[layer],
                        scheme.field_perm,
                        scheme.body_seed,
                        scheme.isa_seed,
                        stack_guard=_region_stack_guard(region, schemes[0].junk_seed),
                    ),
                    junk_rng,
                    extra,
                    entry_prefix=(
                        f"  xor rsi, qword ptr [rsp+{schemes[0].state_offset}]\n"
                        f"  xor r15, qword ptr [rsp+{schemes[0].state_offset}]\n"
                        f"  xor r13, qword ptr [rsp+{schemes[0].state_offset}]\n"
                    ),
                ),
                frozenset(index * 8 for index in slot),
            )
        )

    # The tracer-constant island trails all dispatch tables (outside the checksummed
    # span, which ends at vm_table_0) and precedes the reserved bytecode; the blob
    # assembly patches it once the checksum is known.
    island = tracer_const_island_asm()
    # Reserve every layer's bytecode but the innermost (which is appended).
    reservations = (
        "".join(f"bc_{layer}:\n  .space {lens[layer]}\n" for layer in range(len(layers) - 1))
        + f"bc_{len(layers) - 1}:\n"
    )
    body = (
        entry
        + "".join(layer_bodies)
        + (
            f"vm_exit:\n{cipher_register_slots(reload_seq, frozenset(index * 8 for index in slot))}"
            f"  add rsp, {frame_size_for_seed(schemes[0].junk_seed)}\n"
            f"  jmp {hex(layers[0].exit_vaddr)}\n"
        )
    )
    poly_rng = random.Random(schemes[0].table_key)
    tables = "".join(
        f"vm_table_{layer}:\n"
        + "".join(f"  .long H_{offsets[layer] + j} - vm_table_{layer}\n" for j in range(counts[layer]))
        for layer in range(len(layers))
    )
    # Thread the dispatch: splice a freshly shuffled decode copy in for every back
    # jump to the (now removed) shared dispatcher - handler tails, the entry, the
    # retarget and the enter_inner/inner_exit transfer stubs all end with
    # `jmp vm_dispatch`, so control flows directly handler -> decode -> next
    # handler with no hub block and no two copies sharing a byte layout. One rng
    # seeded from the outer layer's table key keeps the variant sequence
    # deterministic per build.
    asm = thread_back_jumps(
        body + tables + bootstrap_table + island + reservations,
        lambda: _decode_block(poly_rng, schemes[0].state_offset),
    )

    try:
        engine = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, _ = engine.asm(asm, cave_vaddr)
    except keystone.KsError as exc:
        logger.debug("Nested interpreter assembly failed: %s", exc)
        return None
    if not encoding:
        return None

    return _finalize_nested_blob(
        encoding,
        _NestedEncodingContext(
            layers,
            schemes,
            counts,
            offsets,
            lens,
            cave_vaddr,
            compute_build_checksum(
                bytes(engine.asm(asm[: asm.index("vm_bootstrap:") + len("vm_bootstrap:")], cave_vaddr)[0]),
                schemes[0].xor_key,
                schemes[0].checksum_bytewise,
                schemes[0].checksum_reverse,
            ),
        ),
    )


def _encrypt_table(data: bytearray, start: int, count: int, table_key: int) -> None:
    for index in range(count):
        offset = start + index * 4
        encrypted = int.from_bytes(data[offset : offset + 4], "little") ^ table_key
        data[offset : offset + 4] = encrypted.to_bytes(4, "little")
