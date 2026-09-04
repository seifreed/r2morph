"""Bytecode encoding for region virtualization.

Split out of :mod:`code_virtualization_region_codegen` to keep that aggregator
within the file-size budget. :func:`encode_region` performs the two-pass lowering
of a lowered :class:`Region`'s item list to encrypted, position-masked bytecode;
:func:`_item_size` gives each item's encoded byte length (used to assign offsets).
Both are re-exported from :mod:`code_virtualization_region_codegen` so existing
imports keep working.
"""

from __future__ import annotations

from typing import Any

from r2morph.core.constants import ARCH_BITS_64
from r2morph.mutations.code_virtualization_engine import VirtualizedOp
from r2morph.mutations.code_virtualization_region_encoder import RegionEncoder
from r2morph.mutations.code_virtualization_region_models import Region, RegionScheme

_FIXED_SIZE_GROUPS = {
    1: (
        "vbinop",
        "vbinopsynth",
        "vcmpsynth",
        "fsave",
        "frestore",
        "vzeroupper",
        "vzeroall",
        "syscall",
        "rdtsc",
    ),
    2: (
        "vpush",
        "vpop",
        "vpop8",
        "vpop16",
        "vshift",
        "vshiftreg",
        "not",
        "bswap",
        "push",
        "pop",
        "movfromrsp",
        "movtorsp",
        "leave",
        "incdec",
        "setcc",
        "icall",
        "ijmp",
    ),
    3: (
        "shift",
        "imul",
        "cqo",
        "bt",
        "fparith",
        "fparithvex",
        "cvti2f",
        "cvtf2i",
        "fpmovd",
        "fpmovq",
        "fpcmp",
        "fpcmpvex256",
        "fpmov",
        "fppacked",
        "fpmovvex",
        "fpmovvex256",
        "fpmovvexscalar",
        "fpmovvexscalar3",
        "fpmovvexgp",
        "fpmovvexgpd",
        "fpmovmskb",
        "fpmovmskbvex",
        "fpmovmskbvex256",
        "movxreg",
        "cmov",
        "fppackedimm",
    ),
    4: (
        "div",
        "fppackedvex",
        "fppackedvex256",
        "fppackedveximm",
        "fppackedvex256imm",
        "fppackedvex256permilimm",
        "fppackedvex256varpermil",
    ),
    5: (
        "rspadj",
        "jmp",
        "jcc",
        "vcall",
        "call",
        "fppackedvex256var",
        "fppackedvex256permimm",
        "fppackedvexcmp",
        "fppackedvex256cmp",
    ),
    6: (
        "vloadrip",
        "vstorerip",
        "vlearip",
        "fploadrip",
        "fpstorerip",
        "fpploadrip",
        "fppstorerip",
        "fppackedmemrip",
        "fploadvex256rip",
        "fpstorevex256rip",
        "fparithmemrip",
        "fparithvexmemrip",
        "fploadvexrip",
        "fpstorevexrip",
        "fpmovvexmemrip",
        "fpcmpmemrip",
        "btmemrip",
        "divmemrip",
        "pushmemrip",
        "popmemrip",
        "riprel_load",
        "riprel_store",
        "cmpriprel",
        "opriprel",
        "learip",
        "opmemdstrip",
        "callmemrip",
        "atomicmemrip",
        "mxcsrloadrip",
        "mxcsrstorerip",
    ),
    7: (
        "vload",
        "vstore",
        "vlea",
        "vmovx",
        "imul3",
        "load",
        "store",
        "btmem",
        "divmem",
        "notmem",
        "notmemrip",
        "notmemidx",
        "notmemidxnb",
        "fpload",
        "fpstore",
        "fppload",
        "fppstore",
        "fppackedmem",
        "fploadvex256",
        "fpstorevex256",
        "fppackedvexmemrip",
        "fppackedvex256memrip",
        "fppackedveximmmemrip",
        "fppackedvex256immmemrip",
        "fparithmem",
        "fparithvexmem",
        "fploadvex",
        "fpstorevex",
        "fpmovvexmem",
        "fpcmpmem",
        "cmpmem",
        "opmem",
        "lea",
        "opmemdst",
        "movx",
        "callmem",
        "xchgmem",
        "cmpxchgmem",
        "atomicmem",
        "pushmem",
        "popmem",
        "mxcsrload",
        "mxcsrstore",
    ),
    8: (
        "vleaidxnb",
        "fploadidxnb",
        "fpstoreidxnb",
        "fpploadidxnb",
        "fppstoreidxnb",
        "fppackedmemidxnb",
        "fploadvex256idxnb",
        "fpstorevex256idxnb",
        "fppackedvex256mem",
        "fppackedvexmem",
        "fppackedveximmmem",
        "fppackedvex256immmem",
        "fparithmemidxnb",
        "fparithvexmemidxnb",
        "fploadvexidxnb",
        "fpstorevexidxnb",
        "fpmovvexmemidxnb",
        "fpcmpmemidxnb",
        "tlsloadidxnb",
        "tlsstoreidxnb",
        "vloadidxnb",
        "vstoreidxnb",
        "btmemidxnb",
        "divmemidxnb",
        "ijmpmemnb",
        "callmemidxnb",
        "atomicmemidxnb",
        "pushmemidxnb",
        "popmemidxnb",
        "mxcsrloadidxnb",
        "mxcsrstoreidxnb",
    ),
    9: (
        "vloadidx",
        "vstoreidx",
        "vleaidx",
        "vmovxidx",
        "fploadidx",
        "fpstoreidx",
        "fpploadidx",
        "fppstoreidx",
        "fppackedmemidx",
        "fploadvex256idx",
        "fpstorevex256idx",
        "fppackedvexmemidxnb",
        "fppackedvex256memidxnb",
        "fppackedveximmmemidxnb",
        "fppackedvex256immmemidxnb",
        "fparithmemidx",
        "fparithvexmemidxnb",
        "fpmovvexmemidxnb",
        "fpcmpmemidx",
        "tlsloadidx",
        "tlsstoreidx",
        "leaidx",
        "opmemidx",
        "movxidx",
        "ijmpmem",
        "callmemidx",
        "btmemidx",
        "divmemidx",
        "xchgmemidx",
        "cmpxchgmemidx",
        "atomicmemidx",
        "pushmemidx",
        "popmemidx",
        "mxcsrloadidx",
        "mxcsrstoreidx",
        "pushi",
    ),
    10: (
        "fppackedvex256memidx",
        "fppackedvexmemidx",
        "fppackedveximmmemidx",
        "fppackedvex256immmemidx",
        "fparithvexmemidx",
        "fpmovvexmemidx",
    ),
}
_FIXED_ITEM_SIZES = {kind: size for size, kinds in _FIXED_SIZE_GROUPS.items() for kind in kinds}
_IMMEDIATE_MEMORY_BASE_SIZES = {
    "storei": 7,
    "storeirip": 6,
    "storeiidx": 9,
    "storeiidxnb": 8,
}
_IMMEDIATE_MEMORY_WIDTH_INDEXES = {
    "storei": 4,
    "storeirip": 3,
    "storeiidx": 6,
    "storeiidxnb": 5,
}
_VEX_PACKED_COMPARE_MEMORY_SIZES = {
    "fppackedvexcmpmem": 9,
    "fppackedvexcmpmemrip": 8,
    "fppackedvexcmpmemidx": 11,
    "fppackedvexcmpmemidxnb": 10,
    "fppackedvex256cmpmem": 9,
    "fppackedvex256cmpmemrip": 8,
    "fppackedvex256cmpmemidx": 11,
    "fppackedvex256cmpmemidxnb": 10,
}


def _item_size(item: tuple[Any, ...]) -> int:
    kind = item[0]
    size: int | None = None
    if kind == "vpushi":
        size = 1 + (8 if item[2] == ARCH_BITS_64 else 4)
    elif kind in ("op", "opmba", "opsynth"):
        op: VirtualizedOp = item[1]
        size = 2 + (8 if op.width == ARCH_BITS_64 else 4) if op.is_immediate else 3
    elif kind in ("cmp", "test"):
        size = (2 + item[4] // 8) if item[3] else 3
    elif kind in ("tlsload", "tlsstore"):
        size = 6 if item[3] is None else 7
    elif kind in _IMMEDIATE_MEMORY_BASE_SIZES:
        width_index = _IMMEDIATE_MEMORY_WIDTH_INDEXES[kind]
        size = _IMMEDIATE_MEMORY_BASE_SIZES[kind] + (8 if item[width_index] == ARCH_BITS_64 else 4)
    elif kind in _VEX_PACKED_COMPARE_MEMORY_SIZES:
        size = _VEX_PACKED_COMPARE_MEMORY_SIZES[kind]
    return size if size is not None else _FIXED_ITEM_SIZES.get(kind, 1)


def build_ijmp_targets(region: Region) -> list[tuple[int, int]]:
    """Native-address -> bytecode-offset pairs a computed jump may resolve to.

    Mirrors :func:`encode_region`'s offset assignment so a runtime target address
    can be translated to the bytecode offset of its virtualized item, letting an
    ``ijmp`` re-enter the VM at the virtualized copy of its target rather than the
    overwritten native code. Empty unless the dispatch-region contract populated
    ``region.target_map``, so an ordinary region emits no map.
    """
    if not region.target_map:
        return []
    offsets: list[int] = []
    cursor = 0
    for item in region.instructions:
        offsets.append(cursor)
        cursor += _item_size(item)
    pairs: list[tuple[int, int]] = []
    for addr, item_index in sorted(region.target_map.items()):
        if 0 <= item_index < len(offsets):
            pairs.append((addr, offsets[item_index]))
    return pairs


def encode_region(region: Region, scheme: RegionScheme, bytecode_base: int, checksum: int = 0) -> bytes:
    """Two-pass lowering from region items to encrypted bytecode."""
    offsets: list[int] = []
    cursor = 0
    for item in region.instructions:
        offsets.append(cursor)
        cursor += _item_size(item)
    return RegionEncoder(scheme, offsets, bytecode_base, checksum).encode(region.instructions)
