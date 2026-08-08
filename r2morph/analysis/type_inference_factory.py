"""Type construction helpers for type inference."""

from __future__ import annotations

from typing import TYPE_CHECKING

from r2morph.analysis.type_inference_types import PrimitiveType, TypeCategory, TypeInfo

if TYPE_CHECKING:
    from r2morph.analysis.type_inference import TypeInference

_DEFAULT_OPERAND_SIZE = 4

# x86/x86-64 general-purpose register byte sizes, keyed by register name.
# Order is significant: _get_operand_size matches with ``str.startswith`` and
# returns the first hit, so the wider names are listed first.
_X86_REGISTER_SIZES: dict[str, int] = {
    "rax": 8,
    "rbx": 8,
    "rcx": 8,
    "rdx": 8,
    "rsi": 8,
    "rdi": 8,
    "rbp": 8,
    "rsp": 8,
    "r8": 8,
    "r9": 8,
    "r10": 8,
    "r11": 8,
    "r12": 8,
    "r13": 8,
    "r14": 8,
    "r15": 8,
    "eax": 4,
    "ebx": 4,
    "ecx": 4,
    "edx": 4,
    "esi": 4,
    "edi": 4,
    "ebp": 4,
    "esp": 4,
    "r8d": 4,
    "r9d": 4,
    "r10d": 4,
    "r11d": 4,
    "r12d": 4,
    "r13d": 4,
    "r14d": 4,
    "r15d": 4,
    "ax": 2,
    "bx": 2,
    "cx": 2,
    "dx": 2,
    "si": 2,
    "di": 2,
    "bp": 2,
    "sp": 2,
    "r8w": 2,
    "r9w": 2,
    "r10w": 2,
    "r11w": 2,
    "r12w": 2,
    "r13w": 2,
    "r14w": 2,
    "r15w": 2,
    "al": 1,
    "bl": 1,
    "cl": 1,
    "dl": 1,
    "sil": 1,
    "dil": 1,
    "bpl": 1,
    "spl": 1,
    "r8b": 1,
    "r9b": 1,
    "r10b": 1,
    "r11b": 1,
    "r12b": 1,
    "r13b": 1,
    "r14b": 1,
    "r15b": 1,
}


def create_primitive_type(self: TypeInference, primitive: PrimitiveType) -> TypeInfo:
    """Create a primitive type."""
    size_map = {
        PrimitiveType.INT8: 1,
        PrimitiveType.INT16: 2,
        PrimitiveType.INT32: 4,
        PrimitiveType.INT64: 8,
        PrimitiveType.UINT8: 1,
        PrimitiveType.UINT16: 2,
        PrimitiveType.UINT32: 4,
        PrimitiveType.UINT64: 8,
        PrimitiveType.FLOAT32: 4,
        PrimitiveType.FLOAT64: 8,
        PrimitiveType.BOOL: 1,
        PrimitiveType.VOID: 0,
    }
    return TypeInfo(
        type_id=self._new_type_id(),
        category=TypeCategory.PRIMITIVE,
        size=size_map.get(primitive, 0),
        alignment=size_map.get(primitive, 1),
        primitive=primitive,
        confidence=1.0,
    )


def create_pointer_type(self: TypeInference, pointee: TypeInfo | None = None) -> TypeInfo:
    """Create a pointer type."""
    ptr_size = 8
    return TypeInfo(
        type_id=self._new_type_id(),
        category=TypeCategory.POINTER,
        size=ptr_size,
        alignment=ptr_size,
        pointee=pointee,
        confidence=0.9 if pointee else 0.5,
    )


def create_array_type(self: TypeInference, element_type: TypeInfo, count: int) -> TypeInfo:
    """Create an array type."""
    return TypeInfo(
        type_id=self._new_type_id(),
        category=TypeCategory.ARRAY,
        size=element_type.size * count,
        alignment=element_type.alignment,
        element_type=element_type,
        element_count=count,
        confidence=element_type.confidence * 0.9,
    )


def create_struct_type(self: TypeInference, fields: list[tuple[str, TypeInfo, int]]) -> TypeInfo:
    """Create a struct type."""
    total_size = 0
    max_alignment = 1
    for _, type_info, offset in fields:
        if offset + type_info.size > total_size:
            total_size = offset + type_info.size
        if type_info.alignment > max_alignment:
            max_alignment = type_info.alignment

    return TypeInfo(
        type_id=self._new_type_id(),
        category=TypeCategory.STRUCT,
        size=total_size,
        alignment=max_alignment,
        fields=fields,
        confidence=0.8,
    )


def _create_int_type(self: TypeInference, size: int) -> TypeInfo:
    """Create an integer type of given size."""
    size_to_type = {
        1: PrimitiveType.INT8,
        2: PrimitiveType.INT16,
        4: PrimitiveType.INT32,
        8: PrimitiveType.INT64,
    }
    primitive = size_to_type.get(size, PrimitiveType.INT32)
    return create_primitive_type(self, primitive)


def _get_operand_size(self: TypeInference, operand: str) -> int:
    """Get the size of an operand based on register name."""
    operand = operand.lower().strip()

    for reg, size in _X86_REGISTER_SIZES.items():
        if operand.startswith(reg):
            return size

    return _DEFAULT_OPERAND_SIZE


def _extract_operand_size(disasm: str) -> int:
    """Extract operand size from instruction."""
    if "qword" in disasm:
        return 8
    if "dword" in disasm:
        return 4
    if "word" in disasm:
        return 2
    if "byte" in disasm:
        return 1
    return 4
