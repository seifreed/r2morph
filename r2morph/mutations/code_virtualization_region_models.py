"""Shared data types and handler-key naming for region virtualization.

The region lifter (:mod:`code_virtualization_region`) and the interpreter/blob
code generator (:mod:`code_virtualization_region_codegen`) both depend on the
:class:`Region`/:class:`RegionScheme` value objects and on the canonical
item->handler-key mapping. Keeping them here lets the lifter and the code
generator import a common base without importing each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from r2morph.mutations.code_virtualization_engine import VirtualizedOp

# Multiplying a byte by these broadcasts it into every lane of a dword/qword, so
# the per-item position byte (held in r13b) can un-mask a multi-byte immediate or
# displacement the encoder masked byte-wise. Shared by the code generator's
# dispatch/retarget and the handler bodies.
_QWORD_BROADCAST = 0x0101010101010101
_DWORD_BROADCAST = 0x01010101


@dataclass(eq=False, repr=False, slots=True)
class RegionScheme:
    """Per-instance handler layout, bytecode key, and register-slot layout.

    ``dup`` maps each handler key to the tuple of dense opcode indices that
    decode to it: an operation gets one or more interchangeable handler
    instances (each emitted with its own junk), so the opcode->operation map is
    not one-to-one and the same operation can appear as different opcodes in the
    stream. ``slot_perm`` is a per-instance bijection ``logical register index
    -> frame slot``: each register spills to a shuffled slot rather than its
    ModR/M-ordered one, so the context frame cannot be labelled positionally and
    slot indices in the bytecode reveal no register.
    """

    dup: dict[str, tuple[int, ...]]
    xor_key: int
    junk_seed: int
    slot_perm: tuple[int, ...]
    table_key: int
    field_perm: int = 0
    body_seed: int = 0
    checksum_offset: int = 0x88
    flags_offset: int = 0x80
    isa_seed: int = 0
    checksum_bytewise: bool = False
    state_offset: int = 0x218
    checksum_reverse: bool = False


@dataclass(eq=False, repr=False, slots=True)
class Region:
    """A lowered single-exit function ready to encode to VM bytecode.

    ``instructions`` is a flat list of VM items; branch items carry the index
    of their target item. ``exit_vaddr`` is the native terminator the VM jumps
    back to. ``op_keys`` is the set of interpreter handlers the region needs.

    ``target_map`` maps native instruction addresses to item indices for computed
    jumps and statically proven local indirect calls. The boolean below selects
    virtual call/return handling for the latter; external indirect calls remain
    native ABI bridges.
    """

    instructions: list[tuple[Any, ...]]
    exit_vaddr: int
    entry_vaddr: int
    op_keys: set[str]
    body_ranges: list[tuple[int, int]]
    target_map: dict[int, int] = field(default_factory=dict)
    has_internal_indirect_call: bool = False


_KEY_FIELD_INDEXES: dict[str, tuple[int, ...]] = {
    "lea": (4,),
    "learip": (3,),
    "leaidx": (6,),
    "leaidxnb": (5,),
    "opmemidx": (1, 7),
    "incdec": (1, 3),
    "movx": (1, 2, 3),
    "movxidx": (1, 2, 3),
    "movxreg": (1, 2, 3),
    "load": (4,),
    "store": (4,),
    "storei": (4,),
    "storeirip": (3,),
    "storeiidx": (6,),
    "storeiidxnb": (5,),
    "tlsload": (2, 3, 5),
    "tlsstore": (2, 3, 5),
    "tlsloadidx": (2, 7),
    "tlsloadidxnb": (2, 7),
    "tlsstoreidx": (2, 7),
    "tlsstoreidxnb": (2, 7),
    "fpload": (4,),
    "fpstore": (4,),
    "fploadrip": (3,),
    "fpstorerip": (3,),
    "fploadidx": (6,),
    "fpstoreidx": (6,),
    "fploadidxnb": (5,),
    "fpstoreidxnb": (5,),
    "fparith": (1, 4),
    "fparithvex": (1, 5),
    "fparithvexmem": (1, 6),
    "fparithvexmemrip": (1, 5),
    "fparithvexmemidx": (1, 8),
    "fparithvexmemidxnb": (1, 7),
    "fpmovvexscalar": (1,),
    "fpmovvexscalar3": (1,),
    "fploadvex": (4,),
    "fpstorevex": (4,),
    "fploadvexrip": (3,),
    "fpstorevexrip": (3,),
    "fploadvexidx": (6,),
    "fpstorevexidx": (6,),
    "fploadvexidxnb": (5,),
    "fpstorevexidxnb": (5,),
    "fpmovvexmem": (5,),
    "fpmovvexmemrip": (4,),
    "fpmovvexmemidx": (7,),
    "fpmovvexmemidxnb": (6,),
    "fparithmem": (1, 5),
    "fparithmemrip": (1, 4),
    "fparithmemidx": (1, 7),
    "fparithmemidxnb": (1, 7),
    "cvti2f": (1, 2),
    "cvtf2i": (1, 2),
    "fpcmp": (1,),
    "fpcmpmem": (1, 5),
    "fpcmpmemidx": (1, 7),
    "fpcmpmemidxnb": (1, 7),
    "fpmovd": (1,),
    "fpmov": (1,),
    "fppacked": (1,),
    "fppackedimm": (1, 3),
    "fppackedvex": (1,),
    "fppackedveximm": (1, 4),
    "fppackedvex256": (1,),
    "fppackedvex256imm": (1, 4),
    "fppackedvex256mem": (1,),
    "fppackedvex256memrip": (1,),
    "fppackedvex256memidx": (1,),
    "fppackedvex256memidxnb": (1,),
    "fppackedvexmem": (1,),
    "fppackedvexmemrip": (1,),
    "fppackedvexmemidx": (1,),
    "fppackedvexmemidxnb": (1,),
    "fpmovvex": (1,),
    "fpmovvex256": (1,),
    "fppackedmem": (1,),
    "fppackedmemrip": (1,),
    "fppackedmemidx": (1,),
    "fppackedmemidxnb": (1,),
    "riprel_load": (3,),
    "riprel_store": (3,),
    "cmpmem": (4,),
    "cmpriprel": (3,),
    "opmem": (1, 5),
    "opriprel": (1, 4),
    "opmemdst": (1, 5),
    "opmemdstrip": (1, 4),
    "xchgmem": (4,),
    "xchgmemidx": (6,),
    "cmpxchgmem": (4,),
    "cmpxchgmemidx": (6,),
    "vpushi": (2,),
    "vbinop": (1, 2),
    "vbinopsynth": (1, 2),
    "vload": (3,),
    "vstore": (3,),
    "vloadidx": (5,),
    "vstoreidx": (5,),
    "vloadidxnb": (4,),
    "vstoreidxnb": (4,),
    "vloadrip": (2,),
    "vlea": (3,),
    "vlearip": (2,),
    "vleaidx": (5,),
    "vleaidxnb": (4,),
    "vmovx": (1, 2, 3),
    "vmovxidx": (1, 2, 3),
    "vstorerip": (2,),
    "vshift": (1, 3),
    "vshiftreg": (1, 2),
    "vcmpsynth": (1, 2),
    "imul": (3,),
    "imul3": (4,),
    "not": (2,),
    "bswap": (2,),
    "div": (1, 3),
    "cqo": (1,),
    "push": (2,),
    "pop": (2,),
    "rspadj": (1,),
    "jcc": (1,),
    "setcc": (1,),
    "cmov": (1, 4),
    "exit": (1,),
    "vret": (1,),
}

_IDENTITY_KEYS = {
    "fppload",
    "fppstore",
    "fpploadrip",
    "fppstorerip",
    "fpploadidx",
    "fppstoreidx",
    "fpploadidxnb",
    "fppstoreidxnb",
    "fploadvex256",
    "fpstorevex256",
    "fploadvex256rip",
    "fpstorevex256rip",
    "fploadvex256idx",
    "fpstorevex256idx",
    "fploadvex256idxnb",
    "fpstorevex256idxnb",
    "vpush",
    "vpop",
    "vpop8",
    "vpop16",
    "pushi",
    "movfromrsp",
    "movtorsp",
    "leave",
    "call",
    "vcall",
    "icall",
    "callmem",
    "callmemrip",
    "callmemidx",
    "callmemidxnb",
    "jmp",
    "ijmp",
    "ijmpmem",
    "ijmpmemnb",
    "fsave",
    "frestore",
    "vzeroupper",
    "vzeroall",
    "nop",
    "enter_inner",
    "inner_exit",
    "syscall",
}


_CALL_KEY_LENGTHS = {
    "call": 3,
    "icall": 3,
    "callmem": 4,
    "callmemrip": 3,
    "callmemidx": 6,
    "callmemidxnb": 5,
}
_VRET_CLEANUP_INDEX = 2


def _call_key(item: tuple[Any, ...]) -> str:
    kind: str = item[0]
    if len(item) >= _CALL_KEY_LENGTHS[kind]:
        return f"{kind}_{item[-1]}"
    return kind


def _simple_op_key(item: tuple[Any, ...]) -> str | None:
    kind: str = item[0]
    if kind in ("op", "opmba", "opsynth"):
        operation: VirtualizedOp = item[1]
        operand_kind = "i" if operation.is_immediate else "r"
        return f"{kind}_{operation.mnemonic}_{operand_kind}_{operation.width}"
    if kind in ("cmp", "test", "bt"):
        operand_kind = "i" if item[3] else "r"
        return f"{kind}_{operand_kind}_{item[4]}"
    if kind == "shift":
        return f"{item[1]}_{item[4]}"
    if kind in _IDENTITY_KEYS:
        return kind

    return None


def _op_key(item: tuple[Any, ...]) -> str | None:
    kind: str = item[0]
    if kind == "vret" and len(item) > _VRET_CLEANUP_INDEX and int(item[_VRET_CLEANUP_INDEX]) != 0:
        return f"vret_{item[1]}_{item[2]}"
    if kind in _CALL_KEY_LENGTHS:
        return _call_key(item)
    simple_key = _simple_op_key(item)
    if simple_key is not None:
        return simple_key

    field_indexes = _KEY_FIELD_INDEXES.get(kind)
    if field_indexes is None:
        return None
    suffix = "_".join(str(item[index]) for index in field_indexes)
    return f"{kind}_{suffix}"


def _required_key(item: tuple[Any, ...]) -> str:
    """The handler key for an item that must have one (all but exit)."""
    key = _op_key(item)
    if key is None:
        raise ValueError(f"item has no handler key: {item[0]}")
    return key
