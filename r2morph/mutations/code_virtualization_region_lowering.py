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
        [_memory_pop_kind(operation.width), operation.dst_index],
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
    if kind.startswith("opmemimm"):
        return _lower_memory_immediate_arithmetic(item)
    if kind.startswith("shiftmem"):
        return _lower_memory_shift(item)
    return _lower_register_memory_arithmetic(item)


def _lower_register_memory_arithmetic(item: list[Any]) -> list[list[Any]]:
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


def _lower_memory_immediate_arithmetic(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    if kind == "opmemimm":
        _, mnemonic, value, base, displacement, width = item
        return [
            ["vload", base, displacement, width],
            ["vpushi", value, width],
            ["vbinopsynth", mnemonic, width],
            ["vstore", base, displacement, width],
        ]
    if kind == "opmemimmrip":
        _, mnemonic, value, target, width = item
        return [
            ["vloadrip", target, width],
            ["vpushi", value, width],
            ["vbinopsynth", mnemonic, width],
            ["vstorerip", target, width],
        ]
    if kind == "opmemimmidx":
        _, mnemonic, value, base, index, shift, displacement, width = item
        load = ["vloadidx", base, index, shift, displacement, width]
        store = ["vstoreidx", base, index, shift, displacement, width]
        return [load, ["vpushi", value, width], ["vbinopsynth", mnemonic, width], store]
    if kind == "opmemimmidxnb":
        _, mnemonic, value, index, shift, displacement, width = item
        load = ["vloadidxnb", index, shift, displacement, width]
        store = ["vstoreidxnb", index, shift, displacement, width]
        return [load, ["vpushi", value, width], ["vbinopsynth", mnemonic, width], store]
    raise ValueError(f"unsupported immediate memory arithmetic item: {kind}")


def _lower_memory_shift(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    if kind == "shiftmem":
        _, mnemonic, count, base, displacement, width = item
        load = ["vload", base, displacement, width]
        store = ["vstore", base, displacement, width]
    elif kind == "shiftmemrip":
        _, mnemonic, count, target, width = item
        load = ["vloadrip", target, width]
        store = ["vstorerip", target, width]
    elif kind == "shiftmemidx":
        _, mnemonic, count, base, index, shift, displacement, width = item
        load = ["vloadidx", base, index, shift, displacement, width]
        store = ["vstoreidx", base, index, shift, displacement, width]
    else:
        _, mnemonic, count, index, shift, displacement, width = item
        load = ["vloadidxnb", index, shift, displacement, width]
        store = ["vstoreidxnb", index, shift, displacement, width]
    return [load, ["vshift", mnemonic, count, width], store]


def _lower_partial_register_move(item: list[Any]) -> list[list[Any]]:
    _, destination, source, is_immediate, width = item
    value = ["vpushi", source, width] if is_immediate else ["vpush", source]
    return [value, ["vpop8" if width == _BYTE_WIDTH_BITS else "vpop16", destination]]


def _lower_memory_imul(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    if kind == "imulmem":
        _, destination, immediate, base, displacement, width = item
        load = ["vload", base, displacement, width]
    elif kind == "imulmemrip":
        _, destination, immediate, target, width = item
        load = ["vloadrip", target, width]
    elif kind == "imulmemidx":
        _, destination, immediate, base, index, shift, displacement, width = item
        load = ["vloadidx", base, index, shift, displacement, width]
    else:
        _, destination, immediate, index, shift, displacement, width = item
        load = ["vloadidxnb", index, shift, displacement, width]
    return [load, ["vpushi", immediate, width], ["vimul", width], ["vpop", destination]]


def _lower_compare_memory_immediate(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    operation = "test" if kind.startswith("test") else "cmp"
    if kind in ("cmpmemimm", "testmemimm"):
        _, value, base, displacement, width = item
        load = ["vload", base, displacement, width]
    elif kind in ("cmpmemimmidx", "testmemimmidx"):
        _, value, base, index, shift, displacement, width = item
        load = ["vloadidx", base, index, shift, displacement, width]
    elif kind in ("cmpmemimmidxnb", "testmemimmidxnb"):
        _, value, index, shift, displacement, width = item
        load = ["vloadidxnb", index, shift, displacement, width]
    else:
        _, value, target, width = item
        load = ["vloadrip", target, width]
    return [load, ["vpushi", value, width], ["vcmpsynth", operation, width]]


def _lower_shift_compare(item: list[Any]) -> list[list[Any]]:
    kind = item[0]
    if kind == "shift":
        _, mnemonic, register, count, width = item
        result = [["vpush", register], ["vshift", mnemonic, count, width], ["vpop", register]]
    elif kind == "shiftreg":
        _, mnemonic, register, width = item
        result = [["vpush", register], ["vshiftreg", mnemonic, width], ["vpop", register]]
    elif kind in ("shld", "shrd"):
        _, destination, source, count, width = item
        result = [
            ["vpush", destination],
            ["vpush", source],
            ["vdouble_shift", kind, count, width],
            ["vpop", destination],
        ]
    elif kind in ("cmp", "test"):
        _, register, value, immediate, width = item
        right = ["vpushi", value, width] if immediate else ["vpush", value]
        result = [["vpush", register], right, ["vcmpsynth", kind, width]]
    elif kind == "cmpmem":
        _, register, base, displacement, width = item
        result = [["vpush", register], ["vload", base, displacement, width], ["vcmpsynth", "cmp", width]]
    elif kind in (
        "cmpmemimm",
        "cmpmemimmidx",
        "cmpmemimmidxnb",
        "cmpriprelimm",
        "testmemimm",
        "testmemimmidx",
        "testmemimmidxnb",
        "testriprelimm",
    ):
        result = _lower_compare_memory_immediate(item)
    else:
        _, register, target, width = item
        result = [["vpush", register], ["vloadrip", target, width], ["vcmpsynth", "cmp", width]]
    return result


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
            "opmemimm",
            "opmemimmrip",
            "opmemimmidx",
            "opmemimmidxnb",
            "opmemidx",
            "opmemidxnb",
            "opmemdst",
            "opmemdstidx",
            "opmemdstidxnb",
            "opriprel",
            "opmemdstrip",
            "shiftmem",
            "shiftmemrip",
            "shiftmemidx",
            "shiftmemidxnb",
        )
    },
    "movsub": _lower_partial_register_move,
    **{kind: _lower_memory_imul for kind in ("imulmem", "imulmemrip", "imulmemidx", "imulmemidxnb")},
    **{
        kind: _lower_shift_compare
        for kind in (
            "shift",
            "shiftreg",
            "shld",
            "shrd",
            "cmp",
            "test",
            "cmpmem",
            "cmpriprel",
            "cmpmemimm",
            "cmpmemimmidx",
            "cmpmemimmidxnb",
            "cmpriprelimm",
            "testmemimm",
            "testmemimmidx",
            "testmemimmidxnb",
            "testriprelimm",
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
    source_index_map: dict[int, int] | None = None,
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
        elif item[0] in ("jcc", "jrcxz"):
            target_index = 2 if item[0] == "jcc" else 1
            item[target_index] = old_to_new[item[target_index]]
    _remap_index_map(index_map, old_to_new)
    _remap_index_map(source_index_map, old_to_new)
    return lowered


__all__ = ["_remap_index_map", "lower_arith_to_microops"]
