"""Lower region instructions into shared virtual-stack micro-operations."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from r2morph.mutations.code_virtualization_region_handlers import _BYTE_WIDTH_BITS, _WORD_WIDTH_BITS


def _memory_pop_kind(width: int) -> str:
    if width == _BYTE_WIDTH_BITS:
        return "vpop8"
    if width == _WORD_WIDTH_BITS:
        return "vpop16"
    return "vpop"


def _lower_fold(item: list[Any], fold: str, use_superinstructions: bool) -> list[list[Any]]:
    operation = item[1]
    if use_superinstructions and fold == "vbinop":
        return [["vsuper", operation]]
    source = ["vpushi", operation.value, operation.width] if operation.is_immediate else ["vpush", operation.value]
    return [
        ["vpush", operation.dst_index],
        source,
        [fold, operation.mnemonic, operation.width],
        ["vpop", operation.dst_index],
    ]


def _lower_memory(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    if kind == "load":
        _, register, base, displacement, width = item
        lowered = [["vload", base, displacement, width], [_memory_pop_kind(width), register]]
    elif kind == "store":
        _, register, base, displacement, width = item
        lowered = [["vpush", register], ["vstore", base, displacement, width]]
    elif kind == "loadidx":
        _, register, base, index, shift, displacement, width = item
        lowered = [["vloadidx", base, index, shift, displacement, width], [_memory_pop_kind(width), register]]
    elif kind == "storeidx":
        _, register, base, index, shift, displacement, width = item
        lowered = [["vpush", register], ["vstoreidx", base, index, shift, displacement, width]]
    elif kind == "loadidxnb":
        _, register, index, shift, displacement, width = item
        lowered = [["vloadidxnb", index, shift, displacement, width], [_memory_pop_kind(width), register]]
    elif kind == "storeidxnb":
        _, register, index, shift, displacement, width = item
        lowered = [["vpush", register], ["vstoreidxnb", index, shift, displacement, width]]
    elif kind == "riprel_load":
        _, register, target, width = item
        lowered = [["vloadrip", target, width], [_memory_pop_kind(width), register]]
    else:
        _, register, target, width = item
        lowered = [["vpush", register], ["vstorerip", target, width]]
    return lowered


def _lower_memory_arithmetic(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    if kind == "opmem":
        _, mnemonic, register, base, displacement, width = item
        return [
            ["vpush", register],
            ["vload", base, displacement, width],
            ["vbinopsynth", mnemonic, width],
            ["vpop", register],
        ]
    if kind == "opmemidx":
        _, mnemonic, register, base, index, shift, displacement, width = item
        return [
            ["vpush", register],
            ["vloadidx", base, index, shift, displacement, width],
            ["vbinopsynth", mnemonic, width],
            ["vpop", register],
        ]
    if kind == "opmemdst":
        _, mnemonic, register, base, displacement, width = item
        return [
            ["vload", base, displacement, width],
            ["vpush", register],
            ["vbinopsynth", mnemonic, width],
            ["vstore", base, displacement, width],
        ]
    if kind == "opriprel":
        _, mnemonic, register, target, width = item
        return [
            ["vpush", register],
            ["vloadrip", target, width],
            ["vbinopsynth", mnemonic, width],
            ["vpop", register],
        ]
    _, mnemonic, register, target, width = item
    return [
        ["vloadrip", target, width],
        ["vpush", register],
        ["vbinopsynth", mnemonic, width],
        ["vstorerip", target, width],
    ]


def _lower_shift_compare(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    if kind == "shift":
        _, mnemonic, register, count, width = item
        return [["vpush", register], ["vshift", mnemonic, count, width], ["vpop", register]]
    if kind == "shiftreg":
        _, mnemonic, register, width = item
        return [["vpush", register], ["vshiftreg", mnemonic, width], ["vpop", register]]
    if kind in ("cmp", "test"):
        _, register, value, immediate, width = item
        right = ["vpushi", value, width] if immediate else ["vpush", value]
        return [["vpush", register], right, ["vcmpsynth", kind, width]]
    if kind == "cmpmem":
        _, register, base, displacement, width = item
        return [["vpush", register], ["vload", base, displacement, width], ["vcmpsynth", "cmp", width]]
    _, register, target, width = item
    return [["vpush", register], ["vloadrip", target, width], ["vcmpsynth", "cmp", width]]


def _lower_movx_address(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    if kind == "movx":
        _, extension, source_size, width, register, base, displacement = item
        return [["vmovx", extension, source_size, width, base, displacement], ["vpop", register]]
    if kind == "movxidx":
        _, extension, source_size, width, register, base, index, shift, displacement = item
        return [
            ["vmovxidx", extension, source_size, width, base, index, shift, displacement],
            ["vpop", register],
        ]
    if kind == "lea":
        _, register, base, displacement, width = item
        return [["vlea", base, displacement, width], ["vpop", register]]
    if kind == "learip":
        _, register, target, width = item
        return [["vlearip", target, width], ["vpop", register]]
    if kind == "leaidx":
        _, register, base, index, shift, displacement, width = item
        return [["vleaidx", base, index, shift, displacement, width], ["vpop", register]]
    _, register, index, shift, displacement, width = item
    return [["vleaidxnb", index, shift, displacement, width], ["vpop", register]]


_Lowerer = Callable[[list[Any]], list[list[Any]]]
_LOWERERS: dict[str, _Lowerer] = {
    **{
        kind: _lower_memory
        for kind in ("load", "store", "loadidx", "storeidx", "loadidxnb", "storeidxnb", "riprel_load", "riprel_store")
    },
    **{kind: _lower_memory_arithmetic for kind in ("opmem", "opmemidx", "opmemdst", "opriprel", "opmemdstrip")},
    **{kind: _lower_shift_compare for kind in ("shift", "shiftreg", "cmp", "test", "cmpmem", "cmpriprel")},
    **{kind: _lower_movx_address for kind in ("movx", "movxidx", "lea", "learip", "leaidx", "leaidxnb")},
}


def _remap_index_map(index_map: dict[int, int] | None, old_to_new: dict[int, int]) -> None:
    if index_map is None:
        return
    for address, old_index in list(index_map.items()):
        index_map[address] = old_to_new[old_index]


def lower_arith_to_microops(
    items: list[list[Any]],
    index_map: dict[int, int] | None = None,
    use_superinstructions: bool = False,
) -> list[list[Any]]:
    """Lower arithmetic and memory items and remap branch target indices."""
    fold_of = {"opmba": "vbinop", "opsynth": "vbinopsynth"}
    lowered: list[list[Any]] = []
    old_to_new: dict[int, int] = {}
    for old_index, item in enumerate(items):
        old_to_new[old_index] = len(lowered)
        fold = fold_of.get(item[0])
        if fold is not None:
            lowered.extend(_lower_fold(item, fold, use_superinstructions))
            continue
        lowerer = _LOWERERS.get(item[0])
        lowered.extend([item] if lowerer is None else lowerer(item))
    for item in lowered:
        if item[0] in ("jmp", "vcall"):
            item[1] = old_to_new[item[1]]
        elif item[0] == "jcc":
            item[2] = old_to_new[item[2]]
    _remap_index_map(index_map, old_to_new)
    return lowered


__all__ = ["_remap_index_map", "lower_arith_to_microops"]
