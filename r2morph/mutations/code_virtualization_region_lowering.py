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
    if item[1] in ("adc", "sbb"):
        return [item]
    if kind == "opmem":
        _, mnemonic, register, base, displacement, width = item
        return [
            ["vpush", register],
            ["vload", base, displacement, width],
            ["vbinopsynth", mnemonic, width],
            ["vpop", register],
        ]
    if kind in ("opmemidx", "opmemidxnb"):
        if kind == "opmemidxnb":
            _, mnemonic, register, index, shift, displacement, width = item
            load = ["vloadidxnb", index, shift, displacement, width]
        else:
            _, mnemonic, register, base, index, shift, displacement, width = item
            load = ["vloadidx", base, index, shift, displacement, width]
        return [
            ["vpush", register],
            load,
            ["vbinopsynth", mnemonic, width],
            ["vpop", register],
        ]
    if kind in ("opmemdst", "opmemdstidx", "opmemdstidxnb"):
        if kind == "opmemdst":
            _, mnemonic, register, base, displacement, width = item
            load = ["vload", base, displacement, width]
            store = ["vstore", base, displacement, width]
        elif kind == "opmemdstidxnb":
            _, mnemonic, register, index, shift, displacement, width = item
            load = ["vloadidxnb", index, shift, displacement, width]
            store = ["vstoreidxnb", index, shift, displacement, width]
        else:
            _, mnemonic, register, base, index, shift, displacement, width = item
            load = ["vloadidx", base, index, shift, displacement, width]
            store = ["vstoreidx", base, index, shift, displacement, width]
        return [
            load,
            ["vpush", register],
            ["vbinopsynth", mnemonic, width],
            store,
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


def _lower_compare_memory_immediate(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    if kind == "cmpmemimm":
        _, value, base, displacement, width = item
        return [["vload", base, displacement, width], ["vpushi", value, width], ["vcmpsynth", "cmp", width]]
    if kind == "cmpmemimmidx":
        _, value, base, index, shift, displacement, width = item
        return [
            ["vloadidx", base, index, shift, displacement, width],
            ["vpushi", value, width],
            ["vcmpsynth", "cmp", width],
        ]
    if kind == "cmpmemimmidxnb":
        _, value, index, shift, displacement, width = item
        return [
            ["vloadidxnb", index, shift, displacement, width],
            ["vpushi", value, width],
            ["vcmpsynth", "cmp", width],
        ]
    _, value, target, width = item
    return [["vloadrip", target, width], ["vpushi", value, width], ["vcmpsynth", "cmp", width]]


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
    if kind in ("cmpmemimm", "cmpmemimmidx", "cmpmemimmidxnb", "cmpriprelimm"):
        return _lower_compare_memory_immediate(item)
    _, register, target, width = item
    return [["vpush", register], ["vloadrip", target, width], ["vcmpsynth", "cmp", width]]


def _lower_movx_address(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    if kind == "movx":
        _, extension, source_size, width, register, base, displacement = item
        lowered = [["vmovx", extension, source_size, width, base, displacement], ["vpop", register]]
    elif kind == "movxidx":
        _, extension, source_size, width, register, base, index, shift, displacement = item
        lowered = [
            ["vmovxidx", extension, source_size, width, base, index, shift, displacement],
            ["vpop", register],
        ]
    elif kind == "movxidxnb":
        _, extension, source_size, width, register, index, shift, displacement = item
        lowered = [
            ["vmovxidxnb", extension, source_size, width, index, shift, displacement],
            ["vpop", register],
        ]
    elif kind == "lea":
        _, register, base, displacement, width = item
        lowered = [["vlea", base, displacement, width], ["vpop", register]]
    elif kind == "learip":
        _, register, target, width = item
        lowered = [["vlearip", target, width], ["vpop", register]]
    elif kind == "leaidx":
        _, register, base, index, shift, displacement, width = item
        lowered = [["vleaidx", base, index, shift, displacement, width], ["vpop", register]]
    else:
        _, register, index, shift, displacement, width = item
        lowered = [["vleaidxnb", index, shift, displacement, width], ["vpop", register]]
    return lowered


_Lowerer = Callable[[list[Any]], list[list[Any]]]
_LOWERERS: dict[str, _Lowerer] = {
    **{
        kind: _lower_memory
        for kind in ("load", "store", "loadidx", "storeidx", "loadidxnb", "storeidxnb", "riprel_load", "riprel_store")
    },
    **{
        kind: _lower_memory_arithmetic
        for kind in (
            "opmem",
            "opmemidx",
            "opmemidxnb",
            "opmemdst",
            "opmemdstidx",
            "opmemdstidxnb",
            "opriprel",
            "opmemdstrip",
        )
    },
    **{
        kind: _lower_shift_compare
        for kind in (
            "shift",
            "shiftreg",
            "cmp",
            "test",
            "cmpmem",
            "cmpriprel",
            "cmpmemimm",
            "cmpmemimmidx",
            "cmpmemimmidxnb",
            "cmpriprelimm",
        )
    },
    **{kind: _lower_movx_address for kind in ("movx", "movxidx", "movxidxnb", "lea", "learip", "leaidx", "leaidxnb")},
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
