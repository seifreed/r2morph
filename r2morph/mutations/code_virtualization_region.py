"""
Whole-function control-flow virtualization (lifting side).

Where :mod:`code_virtualization_engine` virtualizes a single straight-line
register run, this module lifts an entire function whose every instruction is a
register op, a comparison, or a branch into a :class:`Region`. The control flow
is lowered into VM items: comparisons capture the real RFLAGS into a private
slot, conditional/unconditional branches retarget the bytecode pointer, and
each terminator (``ret``/``swi``/terminal ``syscall``) becomes a distinct VM exit
back to native code (any number of terminators is supported). Returning syscalls
are bridged inside the VM so execution can continue with the next item.

A function that is not fully reducible to this model (a call, a memory operand,
an indirect or out-of-function branch, no terminator) yields ``None`` and is
left untouched.

The interpreter assembly and bytecode generation for a lowered region live in
:mod:`code_virtualization_region_codegen`; the shared value objects in
:mod:`code_virtualization_region_models`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import r2morph.core.randomness as random
from r2morph.mutations import code_virtualization_region_classification as classification
from r2morph.mutations.code_virtualization_engine import (
    GP_REGISTERS,
    RSP_INDEX,
    VirtualizedOp,
)
from r2morph.mutations.code_virtualization_engine_common import _assign_opcode_multiplicity
from r2morph.mutations.code_virtualization_region_lowering import (
    _remap_index_map,
    lower_arith_to_microops,
)
from r2morph.mutations.code_virtualization_region_models import (
    Region,
    RegionScheme,
    _op_key,
)

logger = logging.getLogger(__name__)

_RAX_SLOT = GP_REGISTERS.index("rax")
_RDX_SLOT = GP_REGISTERS.index("rdx")
_CANONICAL_FLAGS_OFFSET = 0x80
_STATE_SLOT_CANDIDATES = tuple(range(0x210, 0x280, 8))


@dataclass
class _RegionBuild:
    items: list[list[Any]]
    item_index_of: dict[int, int]
    exit_addrs: list[int]
    ret_addrs: set[int]
    body: list[dict[str, Any]]


def _writes_register(item: tuple[Any, ...]) -> frozenset[int]:
    """The logical register slots an item writes (empty if it writes no GP register:
    a comparison, a memory store, a stack adjustment, or a branch).

    Used by the stack-balance guard to invalidate a frame-pointer snapshot when the
    snapshot register is overwritten before a ``mov rsp, reg`` consumes it. Most ops
    write one slot; ``div``/``idiv`` write two (quotient to rax, remainder to rdx).
    """
    kind = item[0]
    if kind in ("op", "opmba", "opsynth"):
        op: VirtualizedOp = item[1]
        return frozenset({op.dst_index})
    if kind in (
        "imul",
        "imul3",
        "pop",
        "movfromrsp",
        "leave",
        "load",
        "tlsload",
        "xchgmem",
        "xchgmemidx",
        "riprel_load",
        "lea",
        "learip",
        "leaidx",
        "leaidxnb",
        "loadidx",
        "loadidxnb",
        "not",
        "bswap",
        "atomicmem",
        "atomicmemrip",
        "atomicmemidx",
        "atomicmemidxnb",
    ):
        if kind.startswith("atomic"):
            return frozenset({int(item[2])}) if item[1] == "xadd" else frozenset()
        return frozenset({int(item[1])})
    if kind in ("shift", "shiftreg", "opmem", "opriprel", "opmemidx", "incdec", "setcc", "cmov"):
        return frozenset({int(item[2])})
    if kind in ("movx", "movxidx", "movxreg"):
        return frozenset({int(item[4])})
    special_writes = {
        "cmpxchgmem": frozenset({_RAX_SLOT}),
        "cmpxchgmemidx": frozenset({_RAX_SLOT}),
        "div": frozenset({_RAX_SLOT, _RDX_SLOT}),
        "cqo": frozenset({_RDX_SLOT}),
        "syscall": frozenset({GP_REGISTERS.index("rax"), GP_REGISTERS.index("rcx"), GP_REGISTERS.index("r11")}),
    }
    return special_writes.get(kind, frozenset())


def _merge_stack_state(
    state: list[tuple[int, tuple[int, int] | None] | None],
    work: list[int],
    nxt: int,
    depth: int,
    snapshot: tuple[int, int] | None,
) -> bool:
    """Merge ``(depth, snapshot)`` into successor ``nxt``; return False on a conflict.

    A first visit seeds the state and queues the item; a revisit rejects a depth
    disagreement and weakens the frame-pointer snapshot to ``None`` when the paths
    disagree, re-queuing so the weaker snapshot propagates.
    """
    if not 0 <= nxt < len(state):
        return False
    existing = state[nxt]
    if existing is None:
        state[nxt] = (depth, snapshot)
        work.append(nxt)
        return True
    if existing[0] != depth:
        return False  # paths disagree on stack depth
    merged_snapshot = existing[1] if existing[1] == snapshot else None
    if merged_snapshot != existing[1]:
        state[nxt] = (existing[0], merged_snapshot)
        work.append(nxt)  # snapshot weakened; re-propagate
    return True


def _stack_transition(
    item: list[Any], depth: int, snapshot: tuple[int, int] | None
) -> tuple[int, tuple[int, int] | None] | None:
    kind = item[0]
    if kind in ("push", "pushi"):
        out_depth = depth + 8
    elif kind == "pop":
        out_depth = depth - 8
    elif kind == "rspadj":
        out_depth = depth + (item[2] if item[1] == "sub" else -item[2])
    elif kind == "movtorsp":
        if snapshot is None or item[1] != snapshot[0]:
            return None
        out_depth = snapshot[1]
    elif kind == "leave":
        if snapshot is None or item[1] != snapshot[0]:
            return None
        out_depth = snapshot[1] - 8
    else:
        out_depth = depth
    if out_depth < 0 or (kind in ("exit", "vret") and depth != 0):
        return None
    out_snapshot: tuple[int, int] | None
    if kind == "movfromrsp":
        out_snapshot = (int(item[1]), depth)
    else:
        written = _writes_register(tuple(item))
        out_snapshot = None if snapshot is not None and snapshot[0] in written else snapshot
    return out_depth, out_snapshot


def _stack_successors(item: list[Any], index: int) -> tuple[list[int], int | None]:
    kind = item[0]
    if kind in ("exit", "vret"):
        return [], None
    if kind == "vcall":
        return [index + 1], int(item[1])
    if kind == "jmp":
        return [int(item[1])], None
    if kind == "jcc":
        return [index + 1, int(item[2])], None
    return [index + 1], None


def _stack_states(items: list[list[Any]]) -> list[tuple[int, tuple[int, int] | None] | None] | None:
    """Verify the region's virtual stack is balanced on every path.

    The VM force-restores the hardware rsp on exit, and the function's virtual
    stack traffic happens in a relocated scratch region, so a region is only safe
    if every path reaches each terminator with the stack at its entry depth and
    never underflows (which would read caller stack the VM never modelled). A
    forward dataflow tracks, per item, a byte depth and the frame-pointer
    snapshot ``(register, depth)`` taken by ``mov reg, rsp``: push/pop move 8
    bytes, ``add``/``sub rsp,imm`` move imm, and ``mov rsp,reg``/``leave`` restore
    the depth captured when ``reg`` last copied rsp (rejecting if that register
    was overwritten meanwhile). Conflicting depths, an underflow, or a non-zero
    depth at a terminator rejects the region (left native).
    """
    if not items:
        return None
    # Per item: (byte depth, frame-pointer snapshot (register, depth) or None).
    state: list[tuple[int, tuple[int, int] | None] | None] = [None] * len(items)
    state[0] = (0, None)
    work = [0]
    while work:
        i = work.pop()
        current = state[i]
        if current is None:
            raise RuntimeError("VM stack analysis queued an uninitialized state")
        depth, snapshot = current
        item = items[i]
        transition = _stack_transition(item, depth, snapshot)
        if transition is None:
            return None
        out_depth, out_snapshot = transition
        successors, call_target = _stack_successors(item, i)
        if not successors:
            continue
        if call_target is not None and not _merge_stack_state(state, work, call_target, 0, None):
            return None
        for nxt in successors:
            if not _merge_stack_state(state, work, nxt, out_depth, out_snapshot):
                return None
    return state


def _stack_balanced(items: list[list[Any]]) -> bool:
    """Return whether the region's stack dataflow has one valid state per path."""
    return _stack_states(items) is not None


# Items that fully overwrite every readable arithmetic flag (CF, OF, SF, ZF, PF;
# AF is never read by any conditional jump). They kill an upstream flag value.
_FLAG_KILLER_KINDS = frozenset(
    {
        "cmp",
        "test",
        "cmpmem",
        "cmpriprel",
        "fpcmp",
        "fpcmpvex256",
        "fpcmpmem",
        "fpcmpmemrip",
        "opmem",
        "opriprel",
        "opmemdst",
        "opmemdstrip",
        "opmemidx",
        "call",
        "vcall",
        "icall",
        "callmem",
        "callmemrip",
        "callmemidx",
        "callmemidxnb",
        "cmpxchgmem",
        "cmpxchgmemidx",
        "atomicmem",
        "atomicmemrip",
        "atomicmemidx",
        "atomicmemidxnb",
        "syscall",
    }
)


def _flag_successors(items: list[list[Any]], i: int) -> list[int]:
    kind = items[i][0]
    if kind in ("exit", "vret"):
        return []
    if kind == "jmp":
        return [items[i][1]]
    if kind == "jcc":
        return [i + 1, items[i][2]]
    return [i + 1]


_MBA_OP_MNEMONICS = frozenset({"add", "sub", "xor", "and", "or"})


def _flag_dead_op_indices(items: list[list[Any]]) -> set[int]:
    """Indices of ``add``/``sub`` op items whose flags are dead on every path.

    A conditional jump (``jcc``), a flag save (``fsave``, the virtualized
    ``pushfq``), and a conditional set/move (``setcc``/``cmov``) are the flag
    readers in the virtualizable subset, so an op's flags are dead iff no reachable
    reader consumes them before a full flag-killer (``cmp``/``sub``/...) overwrites
    them.
    The analysis is conservative — every ``jcc`` is treated as reading all flags
    and every terminator as keeping them live — so an add is only marked when its
    flags are provably unread, never the reverse.
    """
    n = len(items)

    def fixed_needed_in(i: int) -> bool | None:
        kind = items[i][0]
        if kind in ("jcc", "exit", "vret", "fsave", "setcc", "cmov"):
            return True  # jcc/fsave/setcc/cmov read flags; exit/vret conservatively keep them live
        if kind in _FLAG_KILLER_KINDS:
            return False
        if kind == "op" and items[i][1].mnemonic != "mov":
            return False  # add/sub/xor/and/or overwrite every readable flag
        return None  # everything else neither reads nor fully kills flags

    needed_in = [False] * n
    changed = True
    while changed:
        changed = False
        for i in range(n):
            fixed = fixed_needed_in(i)
            value = fixed if fixed is not None else any(needed_in[s] for s in _flag_successors(items, i))
            if value != needed_in[i]:
                needed_in[i] = value
                changed = True

    dead = set()
    for i in range(n):
        if (
            items[i][0] == "op"
            and items[i][1].mnemonic in _MBA_OP_MNEMONICS
            and not any(needed_in[s] for s in _flag_successors(items, i))
        ):
            dead.add(i)
    return dead


# Mean junk VM instructions inserted per real item. ``mov reg, reg`` is a perfect
# identity (writes a slot with its own value, sets no flags), so it is
# semantics-preserving for any register at any position - no liveness analysis
# needed - yet it executes a real handler and pads the bytecode with operations a
# devirtualizer cannot distinguish from the program's own. Kept modest so the
# per-run execution cost (and a looping run's total) stays bounded.
_JUNK_OP_PROBABILITY = 0.35


def _lower_arith_to_microops(items: list[list[Any]], index_map: dict[int, int] | None = None) -> list[list[Any]]:
    return lower_arith_to_microops(items, index_map)


def _inject_junk_movs(
    items: list[list[Any]], rng: random.Random, index_map: dict[int, int] | None = None
) -> list[list[Any]]:
    """Sprinkle identity ``mov reg, reg`` items through the resolved item list and
    remap every branch target index to its new position.

    Branches store their target as an item index; inserting items shifts those
    indices, so a position map is built as the new list is assembled and applied to
    every ``jmp``/``vcall``/``jcc`` afterward. Junk is never itself a branch target.
    """
    junk_regs = [index for index in range(len(GP_REGISTERS)) if index != RSP_INDEX]
    new_items: list[list[Any]] = []
    old_to_new: dict[int, int] = {}
    for old_index, item in enumerate(items):
        while rng.random() < _JUNK_OP_PROBABILITY:
            reg = rng.choice(junk_regs)
            new_items.append(["op", VirtualizedOp("mov", reg, reg, False, 64)])
        old_to_new[old_index] = len(new_items)
        new_items.append(item)
    for item in new_items:
        if item[0] in ("jmp", "vcall"):
            item[1] = old_to_new[item[1]]
        elif item[0] == "jcc":
            item[2] = old_to_new[item[2]]
    _remap_index_map(index_map, old_to_new)
    return new_items


def _build_region_items(instructions: list[dict[str, Any]], allow_computed_jump: bool) -> _RegionBuild | None:
    if not instructions:
        return None
    ret_cleanup: dict[int, int] = {}
    for instruction in instructions:
        if instruction.get("type") != "ret":
            continue
        cleanup = classification._decode_ret_cleanup(str(instruction.get("opcode", "")))
        if cleanup is None:
            return None
        ret_cleanup[int(instruction["addr"])] = cleanup
    exit_addrs = sorted(
        {
            instruction["addr"]
            for index, instruction in enumerate(instructions)
            if instruction.get("type") in ("ret", "swi")
            or (
                instruction.get("type") == "syscall"
                and (index + 1 == len(instructions) or instructions[index + 1].get("type") == "ret")
            )
        }
    )
    if not exit_addrs:
        return None
    exit_set = set(exit_addrs)
    ret_addrs = {instruction["addr"] for instruction in instructions if instruction.get("type") == "ret"}
    body = [instruction for instruction in instructions if instruction["addr"] not in exit_set]
    if not body:
        return None
    items: list[list[Any]] = []
    item_index_of: dict[int, int] = {}
    for instruction in body:
        item = classification._classify(instruction, allow_computed_jump=allow_computed_jump)
        if item is None:
            return None
        item_index_of[instruction["addr"]] = len(items)
        items.append(item)
        next_address = instruction["addr"] + instruction.get("size", 0)
        if item[0] not in ("jmp", "ijmp") and next_address in exit_set:
            items.append(["jmp", next_address])
    for address in exit_addrs:
        if address in ret_cleanup:
            items.append(["exit", address, ret_cleanup[address]])
        else:
            items.append(["exit", address])
    return _RegionBuild(items, item_index_of, exit_addrs, ret_addrs, body)


def _resolve_region_targets(build: _RegionBuild, instructions: list[dict[str, Any]]) -> bool:
    exit_index_of = {int(item[1]): index for index, item in enumerate(build.items) if item[0] == "exit"}

    def resolve(target: int) -> int | None:
        return exit_index_of.get(target, build.item_index_of.get(target))

    for item in build.items:
        if item[0] == "jmp":
            resolved = resolve(item[1])
            if resolved is None:
                return False
            item[1] = resolved
        elif item[0] == "jcc":
            resolved = resolve(item[2])
            if resolved is None:
                return False
            item[2] = resolved
    function_start = min(instruction["addr"] for instruction in instructions)
    function_end = max(instruction["addr"] + instruction.get("size", 0) for instruction in instructions)
    has_internal_call = False
    for item in build.items:
        if item[0] == "call" and function_start <= item[1] < function_end and item[1] not in build.ret_addrs:
            resolved = build.item_index_of.get(item[1])
            if resolved is None:
                return False
            item[0] = "vcall"
            item[1] = resolved
            has_internal_call = True
    if has_internal_call:
        for item in build.items:
            if item[0] == "exit" and item[1] in build.ret_addrs:
                item[0] = "vret"
    return True


def _has_static_internal_indirect_call(build: _RegionBuild) -> bool:
    """Recognize an indirect call whose target is proven by local dataflow.

    Register-indirect calls use the last value producer directly. A memory-
    indirect call can use the same proof when the pointer was just stored to
    the exact memory slot from a known local address.
    """
    boundary_kinds = frozenset(
        {
            "call",
            "icall",
            "callmem",
            "callmemrip",
            "callmemidx",
            "callmemidxnb",
            "jmp",
            "jcc",
            "exit",
            "vret",
            "syscall",
        }
    )

    def register_target(index: int, register: int) -> int | None:
        for producer in reversed(build.items[:index]):
            if producer[0] in boundary_kinds:
                break
            if register not in _writes_register(tuple(producer)):
                continue
            if producer[0] == "learip" and producer[1] == register:
                target_value: object = producer[2]
                return target_value if isinstance(target_value, int) else None
            if producer[0] == "op":
                operation: VirtualizedOp = producer[1]
                if operation.mnemonic == "mov" and operation.is_immediate and operation.dst_index == register:
                    immediate_value: object = operation.value
                    return immediate_value if isinstance(immediate_value, int) else None
            break
        return None

    def matches_memory_store(store: list[Any], call: list[Any]) -> bool:
        pairs = {
            "callmem": ("store", (2, 3), (1, 2)),
            "callmemrip": ("riprel_store", (2,), (1,)),
            "callmemidx": ("storeidx", (2, 3, 4, 5), (1, 2, 3, 4)),
            "callmemidxnb": ("storeidxnb", (2, 3, 4), (1, 2, 3)),
        }
        spec = pairs.get(call[0])
        if spec is None or store[0] != spec[0]:
            return False
        store_fields, call_fields = spec[1], spec[2]
        return tuple(store[index] for index in store_fields) == tuple(call[index] for index in call_fields)

    for index, item in enumerate(build.items):
        if item[0] == "icall" and index:
            target = register_target(index, int(item[1]))
        elif item[0] in ("callmem", "callmemrip", "callmemidx", "callmemidxnb") and index:
            target = None
            for store_index in range(index - 1, -1, -1):
                producer = build.items[store_index]
                if producer[0] in boundary_kinds:
                    break
                if matches_memory_store(producer, item):
                    target = register_target(store_index, int(producer[1]))
                    break
            if target is None:
                continue
        else:
            continue
        if target is not None and target in build.item_index_of:
            return True
    return False


def extract_region(
    instructions: list[dict[str, Any]], rng: random.Random | None = None, allow_computed_jump: bool = False
) -> Region | None:
    """Lower a function's linear instruction list into a :class:`Region`.

    Returns ``None`` unless every instruction is a register op, comparison,
    ``nop``, in-function branch, or a terminator (``ret``/``syscall``). Any
    number of terminators is allowed; each becomes a distinct VM exit.

    ``allow_computed_jump`` opts in to the dispatch-region contract: a register-
    indirect jump is lowered to an ``ijmp`` whose runtime target re-enters the VM
    via a target map (native address -> item index) built here. It is off by
    default so the straight-line contract and its guards are unchanged.
    """
    build = _build_region_items(instructions, allow_computed_jump)
    if build is None or not _resolve_region_targets(build, instructions):
        return None
    has_internal_indirect_call = _has_static_internal_indirect_call(build)
    if has_internal_indirect_call:
        for item in build.items:
            if item[0] == "exit" and item[1] in build.ret_addrs:
                item[0] = "vret"
    items = build.items
    stack_states = _stack_states(items)
    if stack_states is None:
        return None
    for index, item in enumerate(items):
        if item[0] in ("call", "icall", "callmem", "callmemrip", "callmemidx", "callmemidxnb"):
            state = stack_states[index]
            if state is None:
                return None
            item.append(state[0])

    # Flag-liveness: an add whose flags are never read becomes an MBA handler
    # (no literal add, no flag capture). Runs before junk injection so the analysis
    # sees only the program's real items.
    for index in _flag_dead_op_indices(items):
        items[index][0] = "opmba"
    # A flag-LIVE arithmetic/boolean op (not marked opmba above) becomes opsynth:
    # the result is computed by MBA and the flags are synthesized by hand, so the
    # handler contains no flag-setting native arithmetic even when a later branch
    # reads its flags.
    for index, item in enumerate(items):
        if item[0] == "op" and item[1].mnemonic in _MBA_OP_MNEMONICS:
            items[index][0] = "opsynth"
    # Lower each arithmetic op (flag-dead opmba and flag-live opsynth) to virtual-stack
    # micro-ops so no handler maps 1:1 to a native mnemonic. Runs after the flag/stack
    # analyses (which see only the program's real items) and before junk injection.
    # A computed jump (ijmp) resolves its target at runtime to a native address in
    # this region; map every body instruction address to its item index so the ijmp
    # handler can re-enter the VM at the virtualized target. Threaded through the
    # lowering and junk passes so the indices stay correct as items shift. Only built
    # when the region actually contains a computed jump; otherwise the map is empty
    # and the region's blob is byte-identical to the straight-line contract's.
    has_computed_jump = any(item[0] in ("ijmp", "ijmpmem", "ijmpmemnb") for item in items)
    target_map: dict[int, int] | None = (
        dict(build.item_index_of) if has_computed_jump or has_internal_indirect_call else None
    )

    items = _lower_arith_to_microops(items, target_map)
    # Junk identity movs (semantics-preserving) padding the bytecode; done after the
    # stack/flag analyses, which the junk does not affect. Rebuild op_keys for the
    # rewritten + augmented items.
    if rng is not None:
        items = _inject_junk_movs(items, rng, target_map)
    op_keys = {key for item in items if (key := _op_key(tuple(item))) is not None}

    body_ranges = [(instruction["addr"], instruction.get("size", 0)) for instruction in build.body]
    return Region(
        [tuple(item) for item in items],
        build.exit_addrs[0],
        build.body[0]["addr"],
        op_keys,
        body_ranges,
        target_map if target_map is not None else {},
        has_internal_indirect_call,
    )


def build_region_scheme(region: Region, rng: random.Random) -> RegionScheme:
    """Assign each handler a dense opcode index plus a bytecode key.

    Opcodes are a per-instance permutation of ``0..N-1`` (N = handler count):
    they index the dispatch table directly, so two builds still share no
    opcode->operation mapping (the permutation differs), but the table stays
    N entries wide instead of a full 256.
    """
    keys = sorted(region.op_keys)
    # Each handler gets several interchangeable instances (never a lone one), shed
    # to fit the single-byte opcode space so opcodes still index the table directly
    # and a value remains above it for the dispatch bounds-guard exit. Shares the
    # engine VM's assignment so both interpreters duplicate handlers identically.
    multiplicity = _assign_opcode_multiplicity(keys, rng)
    total = sum(multiplicity.values())
    indices = rng.sample(range(total), total)
    dup: dict[str, tuple[int, ...]] = {}
    cursor = 0
    for key in keys:
        count = multiplicity[key]
        dup[key] = tuple(indices[cursor : cursor + count])
        cursor += count
    # Leave at least one hole in the historical 16-qword context array and place
    # the displaced register in frame cells unused by both single and nested VMs.
    # This keeps the frame size and every other region stable while denying a
    # decompiler one contiguous register-context signature.
    outlier_slots = (0x90 // 8, 0xA8 // 8)
    outlier_count = rng.randint(1, len(outlier_slots))
    selected_slots = rng.sample(range(len(GP_REGISTERS)), len(GP_REGISTERS) - outlier_count)
    selected_slots.extend(rng.sample(outlier_slots, outlier_count))
    slot_perm = tuple(rng.sample(selected_slots, len(selected_slots)))
    xor_key = rng.randrange(1, 256)
    junk_seed = rng.randrange(1 << 31)
    table_key = rng.randrange(1, 1 << 32)
    field_perm = rng.randrange(1, 1 << 31)
    body_seed = rng.randrange(1 << 31)
    # Drawn last so adding the frame-slot relocation does not shift any earlier
    # field's value for a given seed. The checksum and flags slots are placed in the
    # frame's free middle, qword-aligned and distinct: the checksum in [0x88, 0x100)
    # (never 0x80, which stays reserved as the flag handlers' rendered slot), and the
    # flags slot anywhere in [0x80, 0x100) except the checksum's slot.
    occupied_offsets = {slot * 8 for slot in slot_perm}
    free_offsets = [off for off in range(0x80, 0x100, 8) if off not in occupied_offsets]
    checksum_offset = rng.choice([off for off in free_offsets if off != _CANONICAL_FLAGS_OFFSET])
    flags_offset = rng.choice([off for off in free_offsets if off != checksum_offset])
    # Drawn last so adding the ISA-personality seed does not shift any earlier field's
    # value for a given seed. Selects this build's handler-implementation personality
    # (the flag-synthesis spelling; see code_virtualization_region_isa).
    isa_seed = rng.randrange(1 << 31)
    # Derive the traversal mode without consuming the caller's RNG stream: later
    # handler/junk draws must remain stable when this field is added.
    checksum_bytewise = bool((isa_seed ^ xor_key) & 1)
    checksum_reverse = bool((isa_seed ^ table_key) & 2)
    state_offset = rng.choice(_STATE_SLOT_CANDIDATES)
    return RegionScheme(
        dup,
        xor_key,
        junk_seed,
        slot_perm,
        table_key,
        field_perm,
        body_seed,
        checksum_offset,
        flags_offset,
        isa_seed,
        checksum_bytewise,
        state_offset,
        checksum_reverse,
    )
