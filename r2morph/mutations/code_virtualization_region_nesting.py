"""Nested (multi-layer) region virtualization.

A single virtualized region is one interpreter an analyst peels in one pass.
This module wraps a region in a second VM layer: a contiguous run of plain
register operations is *peeled* out of the outer bytecode into an inner stream
that a second, independently-keyed interpreter executes, reached through an
``enter_inner`` transfer opcode and returning through ``inner_exit``. The two
layers share one register frame (so the peeled run has the same effect it would
have had inline) but have their own opcode permutation, XOR key, dispatch-table
key and dispatch table - so recovering the outer VM only reveals a second VM to
peel.

One shared, slot-driven dispatcher serves both layers: the transfer handlers
write the active layer's opcode key, handler count, dispatch-table base and
table key into frame slots, so every existing handler builder is reused
verbatim (each keeps its own baked operand key and jumps to the one
``vm_dispatch``). Only flag-independent register-op runs are peeled, so no
branch target ever crosses the layer boundary.

The runtime self-checksum (:mod:`code_virtualization_region_integrity`) spans
both layers' code, so tampering with either layer diverges both.
"""

from __future__ import annotations

import logging
import random
import struct
from typing import Any

from r2morph.mutations.code_virtualization_engine import GP_REGISTERS, RSP_INDEX
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import (
    _item_size,
    encode_region,
    handler_instances_asm,
)
from r2morph.mutations.code_virtualization_region_handlers import _FRAME_SIZE, _GUARD
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
    _op_key,
)

logger = logging.getLogger(__name__)

# Frame slots above the checksum byte (0x88) and below the preserved red zone
# (0x100): the dispatcher reads the active layer's parameters from these, the
# transfer handlers write them. Each parent->child transition gets its own
# return-pointer slot at _RETURN_BASE + index*8, so a chain of nested layers
# returns correctly without a runtime stack.
_KEY_OFFSET = 0x90  # active layer opcode XOR key (byte)
_COUNT_OFFSET = 0x98  # active layer handler count (byte)
_TABLE_OFFSET = 0xA0  # active layer dispatch-table base (absolute addr)
_TKEY_OFFSET = 0xA8  # active layer dispatch-table XOR key (dword)
_RETURN_BASE = 0xB0  # first parent-bytecode-pointer return slot

_MIN_PEEL = 2  # shortest op run worth peeling into an inner layer
# Cap layers so the per-transition return slots stay below the red zone (0x100).
_MAX_LAYERS = (0x100 - _RETURN_BASE) // 8


def _key_parts(key: int) -> tuple[str, str]:
    return hex((key * _QWORD_BROADCAST) & 0xFFFFFFFFFFFFFFFF), hex((key * _DWORD_BROADCAST) & 0xFFFFFFFF)


def _peel_op_run(instructions: list[tuple[Any, ...]]) -> tuple[int, int] | None:
    """Find the longest contiguous register-op run safe to move to an inner layer.

    Only ``op``/``opmba`` items are eligible (pure register/immediate arithmetic,
    no memory, stack or control flow). The run's first item may be a branch
    target (a jump to it becomes a jump to the ``enter_inner`` that runs the
    whole run), but no interior item may be, so no branch ever lands mid-run.
    """
    targets: set[int] = set()
    for item in instructions:
        if item[0] == "jmp":
            targets.add(item[1])
        elif item[0] == "jcc":
            targets.add(item[2])

    best: tuple[int, int] | None = None
    i = 0
    n = len(instructions)
    while i < n:
        if instructions[i][0] in ("op", "opmba"):
            j = i + 1
            while j < n and instructions[j][0] in ("op", "opmba") and j not in targets:
                j += 1
            if j - i >= _MIN_PEEL and (best is None or (j - i) > (best[1] - best[0])):
                best = (i, j)
            i = j
        else:
            i += 1
    return best


def split_region(region: Region, rng: random.Random) -> tuple[Region, Region] | None:
    """Split ``region`` into an outer region (with an ``enter_inner`` marker) and
    an inner region (the peeled run plus an ``inner_exit`` terminator)."""
    run = _peel_op_run(region.instructions)
    if run is None:
        return None
    start, end = run
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
    )
    inner = Region(
        inner_items,
        region.exit_vaddr,
        region.entry_vaddr,
        {k for it in inner_items if (k := _op_key(it)) is not None},
        [],
    )
    return outer, inner


def _scheme_count(scheme: RegionScheme) -> int:
    return sum(len(indices) for indices in scheme.dup.values())


def _index_to_key(scheme: RegionScheme, offset: int = 0) -> dict[int, str]:
    return {offset + index: key for key, indices in scheme.dup.items() for index in indices}


def _set_layer_slots(scheme: RegionScheme, layer: int, count: int) -> str:
    """Assembly that points the shared dispatcher at one layer's parameters."""
    return (
        f"  mov byte ptr [rsp+{_KEY_OFFSET}], {scheme.xor_key}\n"
        f"  mov byte ptr [rsp+{_COUNT_OFFSET}], {count}\n"
        f"  lea rax, [rip+vm_table_{layer}]\n"
        f"  mov qword ptr [rsp+{_TABLE_OFFSET}], rax\n"
        f"  mov dword ptr [rsp+{_TKEY_OFFSET}], {hex(scheme.table_key)}\n"
    )


def _enter_inner_asm(child_scheme: RegionScheme, child: int, child_count: int, return_slot: int) -> str:
    """Handler that saves the resume point and transfers down to layer ``child``."""
    return (
        f"  lea rax, [rsi+1]\n  mov qword ptr [rsp+{return_slot}], rax\n"
        + _set_layer_slots(child_scheme, child, child_count)
        + f"  lea rsi, [rip+bc_{child}]\n  mov r15, rsi\n  jmp vm_dispatch\n"
    )


def _inner_exit_asm(parent_scheme: RegionScheme, parent: int, parent_count: int, return_slot: int) -> str:
    """Handler that restores the parent layer's parameters and resumes it."""
    return (
        _set_layer_slots(parent_scheme, parent, parent_count)
        + f"  mov rsi, qword ptr [rsp+{return_slot}]\n  lea r15, [rip+bc_{parent}]\n  jmp vm_dispatch\n"
    )


def _dispatch_asm() -> str:
    # Shared dispatcher: decode the opcode with the active layer's key (frame
    # slot) plus the position mask and the self-checksum, bounds-check against
    # the active handler count, then jump through the active dispatch table.
    return (
        "vm_dispatch:\n"
        "  mov r13, rsi\n  sub r13, r15\n"
        "  movzx eax, byte ptr [rsi]\n"
        f"  xor al, byte ptr [rsp+{_KEY_OFFSET}]\n  xor al, r13b\n  xor al, byte ptr [rsp+{_CHECKSUM_OFFSET}]\n"
        f"  movzx ecx, byte ptr [rsp+{_COUNT_OFFSET}]\n  cmp al, cl\n  jae vm_exit\n"
        f"  mov r14, qword ptr [rsp+{_TABLE_OFFSET}]\n  mov eax, dword ptr [r14+rax*4]\n"
        # Diffuse the table key with the self-checksum (broadcast to 32 bits) so
        # tampering corrupts handler resolution in every layer, not just opcodes.
        f"  xor eax, dword ptr [rsp+{_TKEY_OFFSET}]\n"
        f"  movzx ecx, byte ptr [rsp+{_CHECKSUM_OFFSET}]\n  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n"
        "  movsxd rax, eax\n  add rax, r14\n  jmp rax\n"
    )


def _build_layers(region: Region, depth: int, rng: random.Random) -> list[Region] | None:
    """Recursively peel an op run out of each layer to form a chain of regions.

    Layer 0 is the outermost (entered natively); each later layer is entered from
    its parent and returns to it. Stops at ``depth`` layers or when no further run
    is peelable. Returns ``None`` if nothing peeled (use the single-layer blob).
    """
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


def build_nested_region_blob(region: Region, cave_vaddr: int, rng: random.Random, depth: int = 2) -> bytes | None:
    """Assemble an N-layer nested interpreter for ``region`` at ``cave_vaddr``.

    Each layer is an independently-keyed VM; a peeled register-op run in layer
    ``k`` runs in layer ``k+1``, reached by ``enter_inner`` and returning through
    ``inner_exit``. Returns ``None`` if the region has no peelable run or assembly
    fails, so the caller can fall back to the single-layer blob.
    """
    try:
        import keystone
    except ImportError:
        logger.warning("keystone unavailable; cannot nest region virtualization")
        return None

    layers = _build_layers(region, max(2, min(depth, _MAX_LAYERS)), rng)
    if layers is None:
        return None
    count = len(layers)

    # Build a scheme per layer; all share the outermost slot permutation so every
    # layer reads and writes the same frame slots for a given logical register.
    schemes = [build_region_scheme(layer, rng) for layer in layers]
    slot = schemes[0].slot_perm
    schemes = [RegionScheme(s.dup, s.xor_key, s.junk_seed, slot, s.table_key) for s in schemes]
    counts = [_scheme_count(s) for s in schemes]
    offsets = [sum(counts[:i]) for i in range(count)]  # global handler-index base per layer
    rsp_off = slot[RSP_INDEX] * 8

    spill = "".join(
        f"  mov qword ptr [rsp+{slot[i] * 8}], {name}\n" for i, name in enumerate(GP_REGISTERS) if name != "rsp"
    )
    reload_seq = "".join(
        f"  mov {name}, qword ptr [rsp+{slot[i] * 8}]\n" for i, name in enumerate(GP_REGISTERS) if name != "rsp"
    )

    entry = (
        f"vm_entry:\n  sub rsp, {_FRAME_SIZE}\n{spill}"
        + checksum_prologue_asm(schemes[0].xor_key, end_label="vm_table_0", slot=_CHECKSUM_OFFSET)
        + _set_layer_slots(schemes[0], 0, counts[0])
        + f"  lea rax, [rsp+{_FRAME_SIZE}]\n  sub rax, {_GUARD}\n  mov qword ptr [rsp+{rsp_off}], rax\n"
        + "  lea rsi, [rip+bc_0]\n  mov r15, rsi\n  jmp vm_dispatch\n"
    )

    # Shared junk stream so duplicate handlers across layers stay distinct.
    junk_seed = 0
    for scheme in schemes:
        junk_seed ^= scheme.junk_seed
    junk_rng = random.Random(junk_seed)

    layer_bodies: list[str] = []
    for layer in range(count):
        scheme = schemes[layer]
        key_qword, key_dword = _key_parts(scheme.xor_key)
        extra: dict[str, str] = {}
        if layer + 1 < count:  # transfer down to the next layer
            extra["enter_inner"] = _enter_inner_asm(
                schemes[layer + 1], layer + 1, counts[layer + 1], _RETURN_BASE + layer * 8
            )
        if layer > 0:  # return up to the parent layer
            extra["inner_exit"] = _inner_exit_asm(
                schemes[layer - 1], layer - 1, counts[layer - 1], _RETURN_BASE + (layer - 1) * 8
            )
        retarget = (
            f"  mov eax, dword ptr [rsi+1]\n  xor eax, {key_dword}\n"
            # Un-mask the position the encoder folded into the branch target (r13b
            # holds it from the dispatch), broadcast to 32 bits - keyed by
            # key XOR position like every other operand in this layer's stream.
            f"  movzx r10d, r13b\n  imul r10d, r10d, {hex(_DWORD_BROADCAST)}\n  xor eax, r10d\n"
            f"  lea r9, [rip+bc_{layer}]\n  add r9, rax\n  mov rsi, r9\n  jmp vm_dispatch\n"
        )
        layer_bodies.append(
            handler_instances_asm(
                _index_to_key(scheme, offset=offsets[layer]),
                key=scheme.xor_key,
                key_qword=key_qword,
                key_dword=key_dword,
                rsp_off=rsp_off,
                junk_rng=junk_rng,
                reload_seq=reload_seq,
                retarget=retarget,
                frame_size=_FRAME_SIZE,
                extra=extra,
            )
        )

    tables = "".join(
        f"vm_table_{layer}:\n"
        + "".join(f"  .long H_{offsets[layer] + j} - vm_table_{layer}\n" for j in range(counts[layer]))
        for layer in range(count)
    )
    lens = [sum(_item_size(item) for item in layer.instructions) for layer in layers]
    # Reserve every layer's bytecode but the innermost (which is appended).
    reservations = (
        "".join(f"bc_{layer}:\n  .space {lens[layer]}\n" for layer in range(count - 1)) + f"bc_{count - 1}:\n"
    )

    asm = (
        entry
        + _dispatch_asm()
        + "".join(layer_bodies)
        + f"vm_exit:\n{reload_seq}  add rsp, {_FRAME_SIZE}\n  jmp {hex(layers[0].exit_vaddr)}\n"
        + tables
        + reservations
    )

    try:
        engine = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, _ = engine.asm(asm, cave_vaddr)
    except keystone.KsError as exc:
        logger.debug("Nested interpreter assembly failed: %s", exc)
        return None
    if not encoding:
        return None

    data = bytearray(encoding)
    bc_off = [0] * count
    bc_off[count - 1] = len(data)
    for layer in range(count - 2, -1, -1):
        bc_off[layer] = bc_off[layer + 1] - lens[layer]
    table0_start = bc_off[0] - sum(counts) * 4
    # Checksum covers only the interpreter code (up to the first table), so the
    # table encryption below and the appended bytecode do not perturb the expected
    # value; the encoder folds it into every layer's stream, and each layer's table
    # key is diffused with it too (broadcast to 32 bits).
    checksum = compute_build_checksum(bytes(data[:table0_start]), schemes[0].xor_key)
    chk_broadcast = checksum * 0x01010101
    for layer in range(count):
        table_key = schemes[layer].table_key ^ chk_broadcast
        _encrypt_table(data, table0_start + offsets[layer] * 4, counts[layer], table_key)
    try:
        encoded = [
            encode_region(layers[layer], schemes[layer], cave_vaddr + bc_off[layer], checksum) for layer in range(count)
        ]
    except struct.error:
        logger.debug("rip-relative target out of 32-bit range; cannot nest")
        return None
    for layer in range(count - 1):
        data[bc_off[layer] : bc_off[layer] + lens[layer]] = encoded[layer]
    return bytes(data) + encoded[count - 1]


def _encrypt_table(data: bytearray, start: int, count: int, table_key: int) -> None:
    for index in range(count):
        offset = start + index * 4
        encrypted = int.from_bytes(data[offset : offset + 4], "little") ^ table_key
        data[offset : offset + 4] = encrypted.to_bytes(4, "little")
