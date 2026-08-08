"""Core type inference helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from r2morph.analysis.type_inference_factory import (
    _create_int_type,
    _extract_operand_size,
    _get_operand_size,
    create_array_type,
    create_pointer_type,
    create_primitive_type,
    create_struct_type,
)
from r2morph.analysis.type_inference_types import PrimitiveType, TypeCategory, TypeInfo
from r2morph.core.binary import Binary

if TYPE_CHECKING:
    from r2morph.analysis.type_inference import TypeInference


def infer_type(self: TypeInference, binary: Binary, address: int) -> TypeInfo:
    """Infer the type at a given address."""
    if address in self._address_types:
        return self._address_types[address]

    disasm = binary.get_function_disasm(address)
    if not disasm:
        return TypeInfo(
            type_id=self._new_type_id(),
            category=TypeCategory.UNKNOWN,
            confidence=0.0,
        )

    for insn in disasm:
        if insn.get("offset", 0) == address:
            return _infer_from_instruction(self, binary, insn)

    return TypeInfo(
        type_id=self._new_type_id(),
        category=TypeCategory.UNKNOWN,
        confidence=0.0,
    )


def _infer_from_instruction(self: TypeInference, binary: Binary, insn: dict) -> TypeInfo:
    """Infer type from an instruction."""
    disasm = insn.get("disasm", "").lower()

    if "mov" in disasm:
        return _infer_from_mov(self, binary, insn, disasm)
    elif "lea" in disasm:
        return create_pointer_type(self)
    elif "cmp" in disasm or "test" in disasm:
        return create_primitive_type(self, PrimitiveType.BOOL)
    elif any(x in disasm for x in ["add", "sub", "imul", "mul"]):
        return _infer_arithmetic_type(self, binary, insn, disasm)
    elif any(x in disasm for x in ["xmm", "ymm", "zmm"]):
        return create_primitive_type(self, PrimitiveType.FLOAT64)

    return TypeInfo(
        type_id=self._new_type_id(),
        category=TypeCategory.UNKNOWN,
        confidence=0.0,
    )


def _infer_from_mov(self: TypeInference, binary: Binary, insn: dict, disasm: str) -> TypeInfo:
    """Infer type from mov instruction."""
    parts = disasm.split(None, 1)
    if len(parts) < 2:
        return TypeInfo(
            type_id=self._new_type_id(),
            category=TypeCategory.UNKNOWN,
        )

    operands = parts[1].split(",")
    if len(operands) < 2:
        return TypeInfo(
            type_id=self._new_type_id(),
            category=TypeCategory.UNKNOWN,
        )

    dest = operands[0].strip()
    src = operands[1].strip()

    if src.startswith("0x") or src.startswith("-0x"):
        size = _get_operand_size(self, dest)
        return _create_int_type(self, size)

    if src.startswith("["):
        return create_pointer_type(self)

    if "[" in dest:
        return create_pointer_type(self)

    return TypeInfo(
        type_id=self._new_type_id(),
        category=TypeCategory.UNKNOWN,
    )


def _infer_arithmetic_type(self: TypeInference, binary: Binary, insn: dict, disasm: str) -> TypeInfo:
    """Infer type from arithmetic instruction."""
    operand_size = _extract_operand_size(disasm)
    return _create_int_type(self, operand_size)


def propagate_types(self: TypeInference, binary: Binary, func_addr: int) -> dict[int, TypeInfo]:
    """Propagate types through a function."""
    types: dict[int, TypeInfo] = {}

    disasm = binary.get_function_disasm(func_addr)
    if not disasm:
        return types

    for insn in disasm:
        addr = insn.get("offset", 0)
        type_info = _infer_from_instruction(self, binary, insn)
        if type_info.category != TypeCategory.UNKNOWN:
            types[addr] = type_info

    _propagate_through_phis(self, types)
    _refine_types(self, types)

    return types


def _propagate_through_phis(self: TypeInference, types: dict[int, TypeInfo]) -> None:
    """Propagate types through phi-like constructs."""
    if not types:
        return

    _unify_adjacent_types(self, types)
    _promote_pointer_neighbors(self, types)


def _unify_adjacent_types(self: TypeInference, types: dict[int, TypeInfo]) -> None:
    """Unify the types of values at adjacent (sorted) addresses."""
    addr_list = sorted(types.keys())

    for i in range(1, len(addr_list)):
        prev_addr = addr_list[i - 1]
        curr_addr = addr_list[i]

        prev_type = types[prev_addr]
        curr_type = types[curr_addr]

        if prev_type.category == TypeCategory.UNKNOWN or curr_type.category == TypeCategory.UNKNOWN:
            continue

        if (
            prev_type.category == curr_type.category
            and prev_type.size == curr_type.size
            and prev_type.confidence > curr_type.confidence
        ):
            types[curr_addr] = TypeInfo(
                type_id=curr_type.type_id,
                category=curr_type.category,
                size=curr_type.size,
                alignment=max(prev_type.alignment, curr_type.alignment),
                primitive=prev_type.primitive if prev_type.primitive else curr_type.primitive,
                confidence=(prev_type.confidence + curr_type.confidence) / 2,
            )

        if (
            curr_type.category == TypeCategory.POINTER
            and prev_type.category == TypeCategory.PRIMITIVE
            and prev_type.primitive in (PrimitiveType.UINT64, PrimitiveType.INT64)
        ):
            types[curr_addr] = TypeInfo(
                type_id=curr_type.type_id,
                category=TypeCategory.POINTER,
                size=8,
                alignment=8,
                confidence=max(prev_type.confidence, curr_type.confidence) * 0.9,
            )


def _promote_pointer_neighbors(self: TypeInference, types: dict[int, TypeInfo]) -> None:
    """Promote a 64-bit integer within 32 bytes of a pointer to a pointer."""
    for addr, type_info in types.items():
        if type_info.category != TypeCategory.POINTER:
            continue
        for other_addr, other_type in types.items():
            if other_addr == addr:
                continue
            if other_type.primitive in (PrimitiveType.UINT64, PrimitiveType.INT64) and abs(other_addr - addr) < 32:
                types[other_addr] = TypeInfo(
                    type_id=other_type.type_id,
                    category=TypeCategory.POINTER,
                    size=8,
                    alignment=8,
                    confidence=0.7,
                )
                break


def _refine_types(self: TypeInference, types: dict[int, TypeInfo]) -> None:
    """Refine types based on constraints."""
    if not types:
        return

    addr_list = list(types.keys())

    for i in range(len(addr_list) - 1):
        curr_addr = addr_list[i]
        next_addr = addr_list[i + 1] if i + 1 < len(addr_list) else None
        curr_type = types[curr_addr]

        if curr_type.category == TypeCategory.PRIMITIVE:
            _refine_primitive_to_pointer(self, types, curr_addr, curr_type, next_addr)
        elif curr_type.category == TypeCategory.UNKNOWN:
            _refine_unknown_type(self, types, curr_addr, curr_type)


def _refine_primitive_to_pointer(
    self: TypeInference,
    types: dict[int, TypeInfo],
    curr_addr: int,
    curr_type: TypeInfo,
    next_addr: int | None,
) -> None:
    """Reinterpret a 64-bit integer as a pointer when the value 8 bytes later is a small primitive."""
    if not (curr_type.size == 8 and curr_type.primitive in (PrimitiveType.INT64, PrimitiveType.UINT64)):
        return
    if not (next_addr and (next_addr - curr_addr) == 8):
        return
    next_type = types[next_addr]
    if next_type.category == TypeCategory.PRIMITIVE and next_type.size <= 4:
        types[curr_addr] = TypeInfo(
            type_id=curr_type.type_id,
            category=TypeCategory.POINTER,
            size=8,
            alignment=8,
            confidence=curr_type.confidence * 0.8,
        )


def _refine_unknown_type(
    self: TypeInference,
    types: dict[int, TypeInfo],
    curr_addr: int,
    curr_type: TypeInfo,
) -> None:
    """Assume an unknown 8-byte value is a pointer and an unknown 4-byte value a 32-bit integer."""
    if curr_type.size == 8:
        types[curr_addr] = TypeInfo(
            type_id=curr_type.type_id,
            category=TypeCategory.POINTER,
            size=8,
            alignment=8,
            confidence=0.5,
        )
    elif curr_type.size == 4:
        types[curr_addr] = TypeInfo(
            type_id=curr_type.type_id,
            category=TypeCategory.PRIMITIVE,
            size=4,
            alignment=4,
            primitive=PrimitiveType.INT32,
            confidence=0.5,
        )


__all__ = [
    "create_array_type",
    "create_pointer_type",
    "create_primitive_type",
    "create_struct_type",
    "_create_int_type",
    "_extract_operand_size",
    "_get_operand_size",
    "infer_type",
    "propagate_types",
    "_infer_from_instruction",
    "_infer_from_mov",
    "_infer_arithmetic_type",
    "_propagate_through_phis",
    "_unify_adjacent_types",
    "_promote_pointer_neighbors",
    "_refine_types",
    "_refine_primitive_to_pointer",
    "_refine_unknown_type",
]
