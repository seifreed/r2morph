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
from r2morph.mutations.code_virtualization_region_dataflow import (
    has_static_internal_indirect_call,
)
from r2morph.mutations.code_virtualization_region_dataflow import (
    writes_register as _writes_register,
)
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

_CANONICAL_FLAGS_OFFSET = 0x80
_STATE_SLOT_CANDIDATES = tuple(range(0x210, 0x280, 8))
_TRAILING_PADDING_TYPES = frozenset({"nop", "trap"})
_TRAILING_PADDING_MNEMONICS = frozenset({"nop", "int3", "ud2"})
_NONRETURNING_SYSCALLS = frozenset({60, 231})


@dataclass
class _RegionBuild:
    items: list[list[Any]]
    item_index_of: dict[int, int]
    exit_addrs: list[int]
    ret_addrs: set[int]
    body: list[dict[str, Any]]


def _is_trailing_padding(instruction: dict[str, Any]) -> bool:
    """Recognize disassembler padding that cannot be reached after a terminator."""
    if instruction.get("type") in _TRAILING_PADDING_TYPES:
        return True
    mnemonic = str(instruction.get("opcode", "")).strip().lower().split(" ", 1)[0]
    return mnemonic in _TRAILING_PADDING_MNEMONICS


def _trim_trailing_padding(instructions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop only unreachable padding emitted after the last real instruction."""
    end = len(instructions)
    while end and _is_trailing_padding(instructions[end - 1]):
        end -= 1
    return instructions[:end]


def _is_syscall_instruction(instruction: dict[str, Any]) -> bool:
    """Recognize Linux ``syscall`` regardless of radare2's type spelling."""
    if instruction.get("type") == "syscall":
        return True
    opcode = str(instruction.get("opcode", "")).strip().lower()
    return instruction.get("type") == "swi" and opcode.split(" ", 1)[0] == "syscall"


def _immediate_rax_write(instruction: dict[str, Any]) -> int | None:
    """Return a direct immediate write to ``rax``/``eax`` when one is visible."""
    opcode = str(instruction.get("opcode", "")).strip().lower()
    mnemonic, separator, operands = opcode.partition(" ")
    if mnemonic not in {"mov", "movabs"} or not separator:
        return None
    destination, separator, source = operands.partition(",")
    if not separator or destination.strip() not in {"rax", "eax"}:
        return None
    try:
        value = int(source.strip(), 0)
    except ValueError:
        return None
    return value & 0xFFFFFFFF if destination.strip() == "eax" else value & 0xFFFFFFFFFFFFFFFF


def _syscall_number(instructions: list[dict[str, Any]], index: int) -> int | None:
    """Find a nearby constant syscall number without guessing across control flow."""
    for instruction in reversed(instructions[:index]):
        if instruction.get("type") in {"call", "rcall", "ucall", "jmp", "cjmp", "ret"}:
            return None
        immediate = _immediate_rax_write(instruction)
        if immediate is not None:
            return immediate
        opcode = str(instruction.get("opcode", "")).strip().lower()
        destination = opcode.partition(" ")[2].partition(",")[0].strip()
        if destination in {"rax", "eax", "ax", "al"}:
            return None
    return None


def _is_terminal_syscall(instructions: list[dict[str, Any]], index: int) -> bool:
    """Return whether a syscall cannot return to the following instruction."""
    if not _is_syscall_instruction(instructions[index]):
        return False
    next_index = index + 1
    if next_index == len(instructions) or instructions[next_index].get("type") == "ret":
        return True
    return _syscall_number(instructions, index) in _NONRETURNING_SYSCALLS


def _normalize_syscall_instruction(instruction: dict[str, Any]) -> dict[str, Any]:
    """Map radare2's ``swi`` spelling to the region classifier's syscall kind."""
    if instruction.get("type") != "swi" or not _is_syscall_instruction(instruction):
        return instruction
    normalized = dict(instruction)
    normalized["type"] = "syscall"
    return normalized


_STACK_ARGUMENT_START = 8
_STACK_WORD_BYTES = 8
_DIRECT_STACK_LAYOUTS: dict[str, tuple[int, int, int | None]] = {
    "load": (2, 3, 4),
    "store": (2, 3, 4),
    "opmem": (3, 4, 5),
    "opmemdst": (3, 4, 5),
    "cmpmem": (2, 3, 4),
    "btmem": (1, 2, 5),
    "divmem": (2, 3, 4),
    "notmem": (1, 2, 3),
    "storei": (2, 3, 4),
    "pushmem": (1, 2, 3),
    "popmem": (1, 2, 3),
    "movx": (5, 6, 2),
    "xchgmem": (2, 3, 4),
    "cmpxchgmem": (2, 3, 4),
    "atomicmem": (2, 3, 4),
    "atomicmemimm": (3, 4, 5),
    "lea": (2, 3, 4),
    "callmem": (1, 2, None),
    "fpload": (2, 3, 4),
    "fpstore": (2, 3, 4),
    "fpcmpmem": (3, 4, 5),
    "fparithmem": (3, 4, 5),
    "fparithvexmem": (4, 5, 6),
    "fppackedmem": (3, 4, None),
    "fploadvex": (2, 3, 4),
    "fpstorevex": (2, 3, 4),
    "fploadvex256": (2, 3, None),
    "fpstorevex256": (2, 3, None),
    "fppackedvexmem": (4, 5, None),
    "fppackedvex256mem": (4, 5, None),
    "fppackedveximmmem": (3, 4, None),
    "fppackedvex256immmem": (3, 4, None),
    "fppackedvexcmpmem": (4, 5, None),
    "fppackedvex256cmpmem": (4, 5, None),
}


def _direct_stack_access(item: list[Any]) -> tuple[int, int, int] | None:
    """Return ``(base_slot, displacement, width_bytes)`` for direct memory items."""
    kind = item[0]
    layout = _DIRECT_STACK_LAYOUTS.get(kind)
    if layout is None or len(item) <= max(layout[:2]):
        return None
    base_index, displacement_index, width_index = layout
    if width_index is None:
        width = 8 if kind == "callmem" else 16 if "256" not in kind else 32
    elif len(item) <= width_index:
        return None
    else:
        width = int(item[width_index]) // 8
    return int(item[base_index]), int(item[displacement_index]), width


def _stack_argument_copy_bytes(
    items: list[list[Any]], stack_states: list[tuple[int, tuple[int, int] | None] | None]
) -> int:
    """Find the largest incoming stack range directly addressed by a region."""
    required_end = _STACK_ARGUMENT_START
    for index, item in enumerate(items):
        access = _direct_stack_access(item)
        state = stack_states[index]
        if access is None or state is None or access[0] != RSP_INDEX:
            continue
        _base_slot, displacement, width = access
        original_offset = displacement - state[0]
        if original_offset >= _STACK_ARGUMENT_START:
            required_end = max(required_end, original_offset + width)
    required_bytes = required_end - _STACK_ARGUMENT_START
    return (required_bytes + _STACK_WORD_BYTES - 1) // _STACK_WORD_BYTES * _STACK_WORD_BYTES


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
    elif kind in ("pushmem", "pushmemrip", "pushmemidx", "pushmemidxnb"):
        out_depth = depth + int(item[-1]) // 8
    elif kind in ("pop", "popmem", "popmemrip", "popmemidx", "popmemidxnb"):
        out_depth = depth - (8 if kind == "pop" else int(item[-1]) // 8)
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
        "cmpmemimm",
        "cmpmemimmidx",
        "cmpmemimmidxnb",
        "cmpriprelimm",
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
        "atomicmemimm",
        "atomicmemimmrip",
        "atomicmemimmidx",
        "atomicmemimmidxnb",
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


def _lower_arith_to_microops(
    items: list[list[Any]],
    index_map: dict[int, int] | None = None,
    use_superinstructions: bool = False,
) -> list[list[Any]]:
    return lower_arith_to_microops(items, index_map, use_superinstructions)


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
    instructions = _trim_trailing_padding(instructions)
    instructions = [_normalize_syscall_instruction(instruction) for instruction in instructions]
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
            if instruction.get("type") == "ret"
            or (instruction.get("type") == "swi" and not _is_syscall_instruction(instruction))
            or _is_terminal_syscall(instructions, index)
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
    has_internal_indirect_call = has_static_internal_indirect_call(build.items, build.item_index_of)
    if has_internal_indirect_call:
        for item in build.items:
            if item[0] == "exit" and item[1] in build.ret_addrs:
                item[0] = "vret"
    items = build.items
    stack_states = _stack_states(items)
    if stack_states is None:
        return None
    stack_argument_copy_bytes = _stack_argument_copy_bytes(items, stack_states)
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

    use_superinstructions = rng is not None and bool(rng.randrange(2))
    items = _lower_arith_to_microops(items, target_map, use_superinstructions)
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
        stack_argument_copy_bytes,
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
