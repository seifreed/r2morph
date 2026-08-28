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
    1: ("vbinop", "vbinopsynth", "vcmpsynth", "fsave", "frestore", "syscall"),
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
        "fpcmp",
        "fpmov",
        "fppacked",
        "fppackedvex",
        "fpmovvex",
        "movxreg",
        "cmov",
    ),
    4: ("div",),
    5: ("rspadj", "jmp", "jcc", "vcall", "call"),
    6: (
        "vloadrip",
        "vstorerip",
        "vlearip",
        "fploadrip",
        "fpstorerip",
        "fpploadrip",
        "fppstorerip",
        "fppackedmemrip",
        "fparithmemrip",
        "riprel_load",
        "riprel_store",
        "cmpriprel",
        "opriprel",
        "learip",
        "opmemdstrip",
        "callmemrip",
    ),
    7: (
        "vload",
        "vstore",
        "vlea",
        "vmovx",
        "imul3",
        "load",
        "store",
        "fpload",
        "fpstore",
        "fppload",
        "fppstore",
        "fppackedmem",
        "fparithmem",
        "fpcmpmem",
        "cmpmem",
        "opmem",
        "lea",
        "opmemdst",
        "movx",
        "callmem",
        "xchgmem",
        "cmpxchgmem",
    ),
    8: (
        "vleaidxnb",
        "fploadidxnb",
        "fpstoreidxnb",
        "leaidxnb",
        "ijmpmemnb",
        "callmemidxnb",
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
        "fparithmemidx",
        "leaidx",
        "opmemidx",
        "movxidx",
        "ijmpmem",
        "callmemidx",
        "xchgmemidx",
        "cmpxchgmemidx",
        "pushi",
    ),
}
_FIXED_ITEM_SIZES = {kind: size for size, kinds in _FIXED_SIZE_GROUPS.items() for kind in kinds}


def _item_size(item: tuple[Any, ...]) -> int:
    kind = item[0]
    if kind == "vpushi":
        return 1 + (8 if item[2] == ARCH_BITS_64 else 4)
    if kind in ("op", "opmba", "opsynth"):
        op: VirtualizedOp = item[1]
        if op.is_immediate:
            return 2 + (8 if op.width == ARCH_BITS_64 else 4)
        return 3
    if kind in ("cmp", "test"):
        return (2 + item[4] // 8) if item[3] else 3
    return _FIXED_ITEM_SIZES.get(kind, 1)


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
