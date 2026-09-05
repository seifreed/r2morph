"""Static register dataflow for whole-function VM regions."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_engine import GP_REGISTERS, VirtualizedOp

_RAX_SLOT = GP_REGISTERS.index("rax")
_RDX_SLOT = GP_REGISTERS.index("rdx")
_CALL_KINDS = frozenset({"call", "vcall", "icall", "callmem", "callmemrip", "callmemidx", "callmemidxnb", "syscall"})
_BOUNDARY_KINDS = _CALL_KINDS | {"jmp", "jcc", "exit", "vret"}
_DIRECT_WRITE_KINDS = frozenset(
    {
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
    }
)
_THIRD_FIELD_WRITE_KINDS = frozenset(
    {"shift", "shiftreg", "opmem", "opriprel", "opmemidx", "opmemidxnb", "incdec", "setcc", "cmov"}
)
_FIFTH_FIELD_WRITE_KINDS = frozenset({"movx", "movxidx", "movxidxnb", "movxreg"})
_SPECIAL_WRITES = {
    "lahf": frozenset({_RAX_SLOT}),
    "cmpxchgmem": frozenset({_RAX_SLOT}),
    "cmpxchgmemidx": frozenset({_RAX_SLOT}),
    "div": frozenset({_RAX_SLOT, _RDX_SLOT}),
    "divmem": frozenset({_RAX_SLOT, _RDX_SLOT}),
    "divmemrip": frozenset({_RAX_SLOT, _RDX_SLOT}),
    "divmemidx": frozenset({_RAX_SLOT, _RDX_SLOT}),
    "divmemidxnb": frozenset({_RAX_SLOT, _RDX_SLOT}),
    "cqo": frozenset({_RDX_SLOT}),
    "syscall": frozenset({_RAX_SLOT, GP_REGISTERS.index("rcx"), GP_REGISTERS.index("r11")}),
}


def writes_register(item: tuple[Any, ...]) -> frozenset[int]:
    """Return the architectural GP slots overwritten by one VM item."""
    kind = item[0]
    if kind in ("op", "opmba", "opsynth"):
        operation: VirtualizedOp = item[1]
        return frozenset({operation.dst_index})
    if kind in _DIRECT_WRITE_KINDS:
        return frozenset({int(item[1])})
    if kind.startswith("atomic"):
        return frozenset({int(item[2])}) if item[1] == "xadd" else frozenset()
    if kind in _THIRD_FIELD_WRITE_KINDS:
        return frozenset({int(item[2])})
    if kind in _FIFTH_FIELD_WRITE_KINDS:
        return frozenset({int(item[4])})
    return _SPECIAL_WRITES.get(kind, frozenset())


def _successors(items: list[list[Any]], index: int) -> tuple[int, ...]:
    kind = items[index][0]
    if kind in ("exit", "vret"):
        candidates: tuple[int, ...] = ()
    elif kind == "jmp":
        candidates = (int(items[index][1]),)
    elif kind == "jcc":
        candidates = (index + 1, int(items[index][2]))
    elif kind == "vcall":
        candidates = (index + 1, int(items[index][1]))
    else:
        candidates = (index + 1,)
    return tuple(candidate for candidate in candidates if 0 <= candidate < len(items))


def _constant_definition(item: list[Any]) -> tuple[int, int] | None:
    if item[0] == "learip" and isinstance(item[2], int):
        return int(item[1]), item[2]
    if item[0] != "op":
        return None
    operation: VirtualizedOp = item[1]
    if operation.mnemonic != "mov" or not operation.is_immediate or not isinstance(operation.value, int):
        return None
    return operation.dst_index, operation.value


def _transfer_constants(item: list[Any], incoming: dict[int, int]) -> dict[int, int]:
    outgoing = {} if item[0] in _CALL_KINDS else dict(incoming)
    for register in writes_register(tuple(item)):
        outgoing.pop(register, None)
    definition = _constant_definition(item)
    if definition is not None:
        outgoing[definition[0]] = definition[1]
    return outgoing


def _merge_constants(current: dict[int, int], incoming: dict[int, int]) -> dict[int, int]:
    return {register: value for register, value in current.items() if incoming.get(register) == value}


def _constant_register_states(items: list[list[Any]]) -> list[dict[int, int] | None]:
    """Compute constants that reach each item identically on every CFG path."""
    states: list[dict[int, int] | None] = [None] * len(items)
    if not items:
        return states
    states[0] = {}
    work = [0]
    while work:
        index = work.pop()
        incoming = states[index]
        if incoming is None:
            raise RuntimeError("VM register dataflow queued an uninitialized state")
        outgoing = _transfer_constants(items[index], incoming)
        for successor in _successors(items, index):
            current = states[successor]
            merged = dict(outgoing) if current is None else _merge_constants(current, outgoing)
            if current != merged:
                states[successor] = merged
                work.append(successor)
    return states


def _matches_memory_store(store: list[Any], call: list[Any]) -> bool:
    pairs = {
        "callmem": ("store", (2, 3), (1, 2)),
        "callmemrip": ("riprel_store", (2,), (1,)),
        "callmemidx": ("storeidx", (2, 3, 4, 5), (1, 2, 3, 4)),
        "callmemidxnb": ("storeidxnb", (2, 3, 4), (1, 2, 3)),
    }
    spec = pairs.get(call[0])
    if spec is None or store[0] != spec[0]:
        return False
    return tuple(store[index] for index in spec[1]) == tuple(call[index] for index in spec[2])


def _memory_call_target(items: list[list[Any]], states: list[dict[int, int] | None], call_index: int) -> int | None:
    call = items[call_index]
    for store_index in range(call_index - 1, -1, -1):
        store = items[store_index]
        if store[0] in _BOUNDARY_KINDS:
            break
        if _matches_memory_store(store, call):
            state = states[store_index]
            return None if state is None else state.get(int(store[1]))
    return None


def has_static_internal_indirect_call(items: list[list[Any]], item_index_of: dict[int, int]) -> bool:
    """Return whether CFG reaching definitions prove a local indirect target."""
    states = _constant_register_states(items)
    for index, item in enumerate(items):
        state = states[index]
        if state is None:
            continue
        if item[0] == "icall":
            target = state.get(int(item[1]))
        elif item[0] in ("callmem", "callmemrip", "callmemidx", "callmemidxnb"):
            target = _memory_call_target(items, states, index)
        else:
            continue
        if target in item_index_of:
            return True
    return False
