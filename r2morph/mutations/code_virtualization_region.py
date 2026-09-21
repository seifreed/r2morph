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

A function that is not fully reducible to this model (a memory operand, an
indirect branch, or no terminator) yields ``None`` and is left untouched.
Direct out-of-function terminal jumps are lowered as native tail exits.

The interpreter assembly and bytecode generation for a lowered region live in
:mod:`code_virtualization_region_codegen`; the shared value objects in
:mod:`code_virtualization_region_models`.
"""

from __future__ import annotations

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
    _constant_register_states,
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

_CANONICAL_FLAGS_OFFSET = 0x80
# Keep the runtime state word clear of the native-call MXCSR spill at 0x210.
_STATE_SLOT_CANDIDATES = tuple(range(0x218, 0x280, 8))
_TRAILING_PADDING_TYPES = frozenset({"nop", "trap"})
_TRAILING_PADDING_MNEMONICS = frozenset({"nop", "int3", "ud2"})
_NONRETURNING_SYSCALLS = frozenset({15, 60, 231})
_CALL_SITE_ITEM_KINDS = frozenset({"call", "icall", "callmem", "callmemrip", "callmemidx", "callmemidxnb"})
_FPMOV_MEMORY_ITEM_WITHOUT_SOURCE_FIELDS = 7
_VRET_CLEANUP_FIELD = 2


@dataclass
class _RegionBuild:
    items: list[list[Any]]
    item_index_of: dict[int, int]
    exit_addrs: list[int]
    tail_exit_targets: dict[int, int]
    ret_addrs: set[int]
    body: list[dict[str, Any]]
    call_site_item_of: dict[int, int]


def _record_call_site_item(mapping: dict[int, int], address: int, item_kind: str, item_index: int) -> None:
    if item_kind in _CALL_SITE_ITEM_KINDS:
        mapping[address] = item_index


def _exit_item(address: int, tail_exit_targets: dict[int, int], ret_cleanup: dict[int, int]) -> list[Any]:
    if address in tail_exit_targets:
        return ["exit", tail_exit_targets[address]]
    if address in ret_cleanup:
        return ["exit", address, ret_cleanup[address]]
    return ["exit", address]


def _tail_exit_targets(
    instructions: list[dict[str, Any]],
    instruction_addresses: set[int],
    function_range: tuple[int, int] | None,
    known_function_ranges: tuple[tuple[int, int], ...] | None,
) -> dict[int, int]:
    targets: dict[int, int] = {}
    for instruction in instructions:
        target = instruction.get("jump")
        if instruction.get("type") != "jmp" or not isinstance(target, int) or target in instruction_addresses:
            continue
        if function_range is not None and function_range[0] <= target < function_range[1]:
            continue
        if known_function_ranges and any(start < target < end for start, end in known_function_ranges):
            continue
        targets[int(instruction["addr"])] = target
    return targets


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


def _trim_after_unreferenced_terminal_syscall(instructions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop disassembler tail bytes after a non-returning syscall when unreachable."""
    for index in range(len(instructions)):
        if not _is_terminal_syscall(instructions, index):
            continue
        later_addresses = {int(item["addr"]) for item in instructions[index + 1 :] if "addr" in item}
        if not later_addresses:
            continue
        prior_targets = {
            int(target)
            for item in instructions[:index]
            for target in (item.get("jump"), item.get("fail"))
            if isinstance(target, int)
        }
        if not later_addresses.intersection(prior_targets):
            return instructions[: index + 1]
    return instructions


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
    "opmemimm": (3, 4, 5),
    "shiftmem": (3, 4, 5),
    "imulmem": (3, 4, 5),
    "opmemdst": (3, 4, 5),
    "cmpmem": (2, 3, 4),
    "testmemimm": (2, 3, 4),
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
    "fploadvexpacked": (2, 3, None),
    "fpstorevexpacked": (2, 3, None),
    "fppackedvexmem": (4, 5, None),
    "fppackedvex256mem": (4, 5, None),
    "fppackedveximmmem": (3, 4, None),
    "fppackedvex256immmem": (3, 4, None),
    "fppackedvexcmpmem": (4, 5, None),
    "fppackedvex256cmpmem": (4, 5, None),
}

_INDEXED_MEMORY_LAYOUTS: dict[str, tuple[int | None, int, int, int, int | None, int | None]] = {
    **{
        kind: (2, 3, 4, 5, 6, None)
        for kind in (
            "loadidx",
            "storeidx",
            "cmpmemimmidx",
            "storeiidx",
            "fploadidx",
            "fpstoreidx",
            "fploadvexidx",
            "fpstorevexidx",
            "divmemidx",
            "xchgmemidx",
            "cmpxchgmemidx",
        )
    },
    **{
        kind: (3, 4, 5, 6, 7, None)
        for kind in (
            "opmemidx",
            "opmemimmidx",
            "opmemdstidx",
            "shiftmemidx",
            "imulmemidx",
            "fparithmemidx",
            "fpcmpmemidx",
            "atomicmemidx",
            "atomicmemimmidx",
        )
    },
    **{kind: (1, 2, 3, 4, 5, None) for kind in ("pushmemidx", "popmemidx", "notmemidx")},
    "incdecmemidx": (2, 3, 4, 5, 6, None),
    "movxidx": (5, 6, 7, 8, 2, None),
    "movxidxnb": (None, 5, 6, 7, 2, None),
    "btmemidx": (1, 2, 3, 4, 7, None),
    "callmemidx": (1, 2, 3, 4, None, 8),
    "ijmpmem": (1, 2, 3, 4, None, 8),
    "fparithvexmemidx": (4, 5, 6, 7, 8, None),
    "fpmovvexmemidx": (None, 0, 0, 0, None, None),
    "fpploadidx": (2, 3, 4, 5, None, 16),
    "fppstoreidx": (2, 3, 4, 5, None, 16),
    "fppackedmemidx": (3, 4, 5, 6, None, 16),
    "fppackedvexmemidx": (4, 5, 6, 7, None, 16),
    "fppackedvex256memidx": (4, 5, 6, 7, None, 32),
    "fppackedvexcmpmemidx": (4, 5, 6, 7, None, 16),
    "fppackedvex256cmpmemidx": (4, 5, 6, 7, None, 32),
    "fppackedveximmmemidx": (3, 4, 5, 6, None, 16),
    "fppackedvex256immmemidx": (3, 4, 5, 6, None, 32),
    "fploadvex256idx": (2, 3, 4, 5, None, 32),
    "fpstorevex256idx": (2, 3, 4, 5, None, 32),
    "fploadvexpackedidx": (2, 3, 4, 5, None, 16),
    "fploadvexpackedidxnb": (2, 3, 4, 5, None, 16),
    "fpstorevexpackedidx": (2, 3, 4, 5, None, 16),
    "fpstorevexpackedidxnb": (2, 3, 4, 5, None, 16),
    "mxcsrloadidx": (1, 2, 3, 4, None, 4),
    "mxcsrstoreidx": (1, 2, 3, 4, None, 4),
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


def _indexed_memory_fields(item: list[Any]) -> tuple[int | None, int, int, int, int] | None:
    """Return address fields as ``(base, index, shift, displacement, width)``."""
    kind = item[0]
    no_base = kind.endswith("idxnb")
    layout = _INDEXED_MEMORY_LAYOUTS.get(kind)
    if layout is None and no_base:
        layout = _INDEXED_MEMORY_LAYOUTS.get(kind[:-2])
    if layout is None:
        return None
    base_index, index_index, shift_index, displacement_index, width_index, fixed_width = layout
    if kind in ("fpmovvexmemidx", "fpmovvexmemidxnb"):
        offset = 1 if no_base else 0
        base_index, index_index, shift_index, displacement_index, width_index = (
            (2, 3, 4, 5, 6) if len(item) == _FPMOV_MEMORY_ITEM_WITHOUT_SOURCE_FIELDS - offset else (3, 4, 5, 6, 7)
        )
        if no_base:
            base_index = None
            index_index -= 1
            shift_index -= 1
            displacement_index -= 1
            width_index -= 1
    elif no_base and base_index is not None:
        base_index = None
        index_index -= 1
        shift_index -= 1
        displacement_index -= 1
        if width_index is not None:
            width_index -= 1
    indexes = (index_index, shift_index, displacement_index)
    if any(len(item) <= index for index in indexes) or (base_index is not None and len(item) <= base_index):
        return None
    if width_index is None:
        if fixed_width is None:
            return None
        width = fixed_width
    elif len(item) <= width_index:
        return None
    else:
        width = int(item[width_index]) // 8
    return (
        None if base_index is None else int(item[base_index]),
        int(item[index_index]),
        int(item[shift_index]),
        int(item[displacement_index]),
        width,
    )


def _stack_argument_copy_bytes(
    items: list[list[Any]], stack_states: list[tuple[int, tuple[int, int] | None] | None]
) -> int | None:
    """Find the largest incoming stack range directly addressed by a region."""
    required_end = _STACK_ARGUMENT_START
    constant_states = _constant_register_states(items)
    for index, item in enumerate(items):
        access = _direct_stack_access(item)
        state = stack_states[index]
        indexed = _indexed_memory_fields(item)
        if (
            indexed is None
            and item[0].endswith(("idx", "idxnb"))
            and not (item[0] in ("leaidx", "leaidxnb") or item[0].startswith("tls"))
        ):
            return None
        if indexed is not None:
            base, index_slot, shift, displacement, width = indexed
            if base is None:
                if index_slot == RSP_INDEX:
                    return None
                continue
            if base != RSP_INDEX:
                continue
            constants = constant_states[index]
            if constants is None or index_slot not in constants or state is None:
                return None
            displacement += constants[index_slot] * (1 << shift)
        else:
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


def _stack_depth_transition(item: list[Any], depth: int, snapshot: tuple[int, int] | None) -> int | None:
    kind = item[0]
    if kind in ("push", "pushi", "enter"):
        out_depth = depth + 8 + (int(item[2]) if kind == "enter" else 0)
    elif kind in ("pushmem", "pushmemrip", "pushmemidx", "pushmemidxnb"):
        out_depth = depth + int(item[-1]) // 8
    elif kind in ("pop", "popmem", "popmemrip", "popmemidx", "popmemidxnb"):
        out_depth = depth - (8 if kind == "pop" else int(item[-1]) // 8)
    elif kind == "rspadj":
        out_depth = depth + (item[2] if item[1] == "sub" else -item[2])
    elif kind == "rspalign":
        # SysV x86-64 function entry has rsp % 16 == 8. The virtual stack depth
        # therefore grows by the current rsp remainder when aligning down.
        out_depth = depth + ((8 - depth) % int(item[1]))
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
    return out_depth


def _stack_transition(
    item: list[Any], depth: int, snapshot: tuple[int, int] | None
) -> tuple[int, tuple[int, int] | None] | None:
    kind = item[0]
    out_depth = _stack_depth_transition(item, depth, snapshot)
    if out_depth is None:
        return None
    if out_depth < 0 or (kind in ("exit", "vret") and depth != 0):
        return None
    out_snapshot: tuple[int, int] | None
    if kind == "enter":
        out_snapshot = (int(item[1]), depth + 8)
    elif kind == "movfromrsp" and (snapshot is None or snapshot[0] == int(item[1])):
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
    if kind in ("jcc", "jrcxz"):
        target = item[2] if kind == "jcc" else item[1]
        return [index + 1, int(target)], None
    return [index + 1], None


def _vcall_return_cleanup(items: list[list[Any]], start: int) -> int | None:
    """Return one cleanup amount for every return reachable from a virtual call."""
    pending = [start]
    visited: set[int] = set()
    cleanups: set[int] = set()
    while pending:
        index = pending.pop()
        if index in visited or not 0 <= index < len(items):
            continue
        visited.add(index)
        item = items[index]
        if item[0] == "vret":
            cleanups.add(int(item[_VRET_CLEANUP_FIELD]) if len(item) > _VRET_CLEANUP_FIELD else 0)
            continue
        if item[0] == "exit":
            return None
        successors, _ = _stack_successors(item, index)
        pending.extend(successors)
    return next(iter(cleanups)) if len(cleanups) == 1 else None


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
            caller_depth = out_depth
            if item[0] == "vcall":
                cleanup = _vcall_return_cleanup(items, call_target if call_target is not None else -1)
                if cleanup is None:
                    return None
                if cleanup <= caller_depth:
                    caller_depth -= cleanup
            if not _merge_stack_state(state, work, nxt, caller_depth, out_snapshot):
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
        "tlsopmem",
        "tlsopmemdst",
        "tlscmp",
        "opriprel",
        "opmemdst",
        "opmemdstrip",
        "opmemimm",
        "opmemimmrip",
        "opmemimmidx",
        "opmemimmidxnb",
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
        "neg",
        "shld",
        "shrd",
        "vdouble_shift",
    }
)


def _flag_successors(items: list[list[Any]], i: int) -> list[int]:
    kind = items[i][0]
    if kind in ("exit", "vret"):
        return []
    if kind == "jmp":
        return [items[i][1]]
    if kind in ("jcc", "jrcxz"):
        target = items[i][2] if kind == "jcc" else items[i][1]
        return [i + 1, target]
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
        if kind == "string" and items[i][1] in {"cmps", "scas"}:
            return False
        if kind in ("jcc", "exit", "vret", "fsave", "lahf", "sahf", "setcc", "cmov"):
            return True  # lahf reads flags; sahf leaves OF live while replacing the other status flags
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
    source_index_map: dict[int, int] | None = None,
) -> list[list[Any]]:
    return lower_arith_to_microops(items, index_map, use_superinstructions, source_index_map)


def _inject_junk_movs(
    items: list[list[Any]],
    rng: random.Random,
    index_map: dict[int, int] | None = None,
    source_index_map: dict[int, int] | None = None,
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
        elif item[0] in ("jcc", "jrcxz"):
            target_index = 2 if item[0] == "jcc" else 1
            item[target_index] = old_to_new[item[target_index]]
    _remap_index_map(index_map, old_to_new)
    _remap_index_map(source_index_map, old_to_new)
    return new_items


def _build_region_items(
    instructions: list[dict[str, Any]],
    allow_computed_jump: bool,
    function_range: tuple[int, int] | None,
    known_function_ranges: tuple[tuple[int, int], ...] | None,
) -> _RegionBuild | None:
    instructions = _trim_trailing_padding(instructions)
    instructions = [_normalize_syscall_instruction(instruction) for instruction in instructions]
    instructions = _trim_after_unreferenced_terminal_syscall(instructions)
    if not instructions:
        return None
    instruction_addresses = {int(instruction["addr"]) for instruction in instructions}
    tail_exit_targets = _tail_exit_targets(instructions, instruction_addresses, function_range, known_function_ranges)
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
            or instruction["addr"] in tail_exit_targets
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
    call_site_item_of: dict[int, int] = {}
    for instruction in body:
        item = classification._classify(instruction, allow_computed_jump=allow_computed_jump)
        if item is None:
            return None
        item_index_of[instruction["addr"]] = len(items)
        _record_call_site_item(call_site_item_of, instruction["addr"], item[0], len(items))
        items.append(item)
        next_address = instruction["addr"] + instruction.get("size", 0)
        if item[0] not in ("jmp", "ijmp", "ijmpmemrip") and next_address in exit_set:
            items.append(["jmp", next_address])
    for address in exit_addrs:
        items.append(_exit_item(address, tail_exit_targets, ret_cleanup))
    return _RegionBuild(items, item_index_of, exit_addrs, tail_exit_targets, ret_addrs, body, call_site_item_of)


def _resolve_call_targets(
    build: _RegionBuild,
    instructions: list[dict[str, Any]],
    function_start: int,
    function_end: int,
    known_function_starts: set[int],
) -> bool:
    instruction_ranges = tuple(
        (int(instruction["addr"]), int(instruction["addr"]) + int(instruction.get("size", 0)))
        for instruction in instructions
        if int(instruction.get("size", 0)) > 0
    )
    for item in build.items:
        if (
            item[0] != "call"
            or not function_start <= item[1] < function_end
            or item[1] in build.ret_addrs
            or item[1] in known_function_starts
        ):
            continue
        resolved = build.item_index_of.get(item[1])
        if resolved is None:
            if any(start < item[1] < end for start, end in instruction_ranges):
                return False
            continue
        item[0] = "vcall"
        item[1] = resolved
    return True


def _resolve_region_targets(
    build: _RegionBuild,
    instructions: list[dict[str, Any]],
    known_function_ranges: tuple[tuple[int, int], ...] | None = None,
) -> bool:
    exit_index_of = {int(item[1]): index for index, item in enumerate(build.items) if item[0] == "exit"}
    try:
        exit_index_of.update({source: exit_index_of[target] for source, target in build.tail_exit_targets.items()})
    except KeyError:
        return False

    def resolve(target: int) -> int | None:
        return exit_index_of.get(target, build.item_index_of.get(target))

    for item in build.items:
        if item[0] == "jmp":
            resolved = resolve(item[1])
            if resolved is None:
                return False
            item[1] = resolved
        elif item[0] in ("jcc", "jrcxz"):
            target_index = 2 if item[0] == "jcc" else 1
            resolved = resolve(item[target_index])
            if resolved is None:
                return False
            item[target_index] = resolved
    function_start = min(instruction["addr"] for instruction in instructions)
    function_end = max(instruction["addr"] + instruction.get("size", 0) for instruction in instructions)
    known_function_starts = {
        start for start, end in known_function_ranges or () if start != function_start and start < end
    }
    if not _resolve_call_targets(build, instructions, function_start, function_end, known_function_starts):
        return False
    if any(item[0] == "vcall" for item in build.items):
        for item in build.items:
            if item[0] == "exit" and item[1] in build.ret_addrs:
                item[0] = "vret"
    return True


def extract_region(
    instructions: list[dict[str, Any]],
    rng: random.Random | None = None,
    allow_computed_jump: bool = False,
    function_range: tuple[int, int] | None = None,
    known_function_ranges: tuple[tuple[int, int], ...] | None = None,
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
    build = _build_region_items(instructions, allow_computed_jump, function_range, known_function_ranges)
    if build is None or not _resolve_region_targets(build, instructions, known_function_ranges):
        return None
    has_internal_indirect_call = has_static_internal_indirect_call(build.items, build.item_index_of)
    if has_internal_indirect_call:
        for item in build.items:
            if item[0] == "exit" and item[1] in build.ret_addrs:
                item[0] = "vret"
    items = build.items
    call_site_item_of = dict(build.call_site_item_of)
    if (stack_states := _stack_states(items)) is None or (
        stack_argument_copy_bytes := _stack_argument_copy_bytes(items, stack_states)
    ) is None:
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
    has_computed_jump = any(item[0] in ("ijmp", "ijmpmem", "ijmpmemnb", "ijmpmemrip") for item in items)
    target_map: dict[int, int] | None = (
        dict(build.item_index_of) if has_computed_jump or has_internal_indirect_call else None
    )

    use_superinstructions = rng is not None and bool(rng.randrange(2))
    items = _lower_arith_to_microops(items, target_map, use_superinstructions, call_site_item_of)
    # Junk identity movs (semantics-preserving) padding the bytecode; done after the
    # stack/flag analyses, which the junk does not affect. Rebuild op_keys for the
    # rewritten + augmented items.
    if rng is not None:
        items = _inject_junk_movs(items, rng, target_map, call_site_item_of)
    op_keys = {key for item in items if (key := _op_key(tuple(item))) is not None}
    body_ranges = [(instruction["addr"], instruction.get("size", 0)) for instruction in build.body]
    sizes = {int(instruction["addr"]): int(instruction.get("size", 0)) for instruction in build.body}
    call_site_items = tuple(
        (address, address + sizes[address], item_index)
        for address, item_index in sorted(call_site_item_of.items())
        if sizes.get(address, 0) > 0
    )
    exit_vaddr = next(
        (address for address in build.exit_addrs if address not in build.tail_exit_targets),
        next(iter(build.tail_exit_targets.values()), build.exit_addrs[0]),
    )
    return Region(
        [tuple(item) for item in items],
        exit_vaddr,
        build.body[0]["addr"],
        op_keys,
        body_ranges,
        target_map if target_map is not None else {},
        has_internal_indirect_call,
        stack_argument_copy_bytes,
        call_site_items,
    )


def region_preserves_unwind_contract(region: Region, frame: Any) -> bool:
    """Return whether replacing ``region`` leaves language-level unwind edges native.

    A VM region has an ordinary FDE, but it cannot yet encode dynamic LSDA
    selection for handlers shared by multiple native-call bridges. It is safe
    to use that FDE only when every parsed protected call-site and landing pad
    remains outside the replaced native ranges.
    """
    lsda_address = getattr(frame, "lsda_address", None)
    landing_pads = getattr(frame, "landing_pads", ())
    if lsda_address is None and not landing_pads:
        return True
    if not landing_pads:
        return False

    def overlaps(address: int, size: int) -> bool:
        return any(start < address + size and address < start + length for start, length in region.body_ranges)

    for landing_pad in landing_pads:
        if not isinstance(landing_pad.address, int) or overlaps(landing_pad.address, max(1, landing_pad.size)):
            return False
        metadata = landing_pad.metadata
        call_sites = [metadata, *metadata.get("call_sites", [])]
        if any(
            not isinstance(site, dict)
            or not isinstance(site.get("call_site_start"), int)
            or not isinstance(site.get("call_site_end"), int)
            or site["call_site_end"] <= site["call_site_start"]
            or overlaps(site["call_site_start"], site["call_site_end"] - site["call_site_start"])
            for site in call_sites
        ):
            return False
    return True


def _landing_pad_call_sites(landing_pad: Any) -> tuple[tuple[int, int], ...] | None:
    metadata = landing_pad.metadata
    if not isinstance(metadata, dict):
        return None
    sites = (metadata, *metadata.get("call_sites", []))
    ranges: list[tuple[int, int]] = []
    for site in sites:
        if not isinstance(site, dict):
            return None
        start = site.get("call_site_start")
        end = site.get("call_site_end")
        if not isinstance(start, int) or not isinstance(end, int) or end <= start:
            return None
        ranges.append((start, end))
    return tuple(ranges)


def region_supports_unwind_contract(region: Region, frame: Any) -> bool:
    """Return whether protected call-sites can be remapped into this region."""
    lsda_address = getattr(frame, "lsda_address", None)
    landing_pads = getattr(frame, "landing_pads", ())
    if lsda_address is None and not landing_pads:
        return True
    if not landing_pads:
        return False

    def overlaps(address: int, size: int) -> bool:
        return any(start < address + size and address < start + length for start, length in region.body_ranges)

    mapped_ranges = tuple((start, end) for start, end, _item_index in region.call_site_items)
    protected_site_in_region = False
    for landing_pad in landing_pads:
        if not isinstance(landing_pad.address, int) or overlaps(landing_pad.address, max(1, landing_pad.size)):
            return False
        call_site_ranges = _landing_pad_call_sites(landing_pad)
        if call_site_ranges is None:
            return False
        for start, end in call_site_ranges:
            if overlaps(start, end - start):
                protected_site_in_region = True
                if not any(call_start < end and start < call_end for call_start, call_end in mapped_ranges):
                    return False
    return not protected_site_in_region or (
        getattr(frame, "lsda_template", None) is not None and isinstance(getattr(frame, "personality", None), int)
    )


def build_region_scheme(region: Region, rng: random.Random, dispatch_variant: int | None = None) -> RegionScheme:
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
    if dispatch_variant is None:
        dispatch_variant = rng.randrange(2)
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
        dispatch_variant,
    )
