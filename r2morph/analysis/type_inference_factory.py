"""Type construction helpers for type inference."""

from __future__ import annotations

from typing import Any

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


def create_primitive_type(self: Any, primitive: Any) -> Any:
    """Create a primitive type."""
    size_map = {
        self.PrimitiveType.INT8: 1,
        self.PrimitiveType.INT16: 2,
        self.PrimitiveType.INT32: 4,
        self.PrimitiveType.INT64: 8,
        self.PrimitiveType.UINT8: 1,
        self.PrimitiveType.UINT16: 2,
        self.PrimitiveType.UINT32: 4,
        self.PrimitiveType.UINT64: 8,
        self.PrimitiveType.FLOAT32: 4,
        self.PrimitiveType.FLOAT64: 8,
        self.PrimitiveType.BOOL: 1,
        self.PrimitiveType.VOID: 0,
    }
    return self.TypeInfo(
        type_id=self._new_type_id(),
        category=self.TypeCategory.PRIMITIVE,
        size=size_map.get(primitive, 0),
        alignment=size_map.get(primitive, 1),
        primitive=primitive,
        confidence=1.0,
    )


def create_pointer_type(self: Any, pointee: Any | None = None) -> Any:
    """Create a pointer type."""
    ptr_size = 8
    return self.TypeInfo(
        type_id=self._new_type_id(),
        category=self.TypeCategory.POINTER,
        size=ptr_size,
        alignment=ptr_size,
        pointee=pointee,
        confidence=0.9 if pointee else 0.5,
    )


def create_array_type(self: Any, element_type: Any, count: int) -> Any:
    """Create an array type."""
    return self.TypeInfo(
        type_id=self._new_type_id(),
        category=self.TypeCategory.ARRAY,
        size=element_type.size * count,
        alignment=element_type.alignment,
        element_type=element_type,
        element_count=count,
        confidence=element_type.confidence * 0.9,
    )


def create_struct_type(self: Any, fields: list[tuple[str, Any, int]]) -> Any:
    """Create a struct type."""
    total_size = 0
    max_alignment = 1
    for _, type_info, offset in fields:
        if offset + type_info.size > total_size:
            total_size = offset + type_info.size
        if type_info.alignment > max_alignment:
            max_alignment = type_info.alignment

    return self.TypeInfo(
        type_id=self._new_type_id(),
        category=self.TypeCategory.STRUCT,
        size=total_size,
        alignment=max_alignment,
        fields=fields,
        confidence=0.8,
    )


def _create_int_type(self: Any, size: int) -> Any:
    """Create an integer type of given size."""
    size_to_type = {
        1: self.PrimitiveType.INT8,
        2: self.PrimitiveType.INT16,
        4: self.PrimitiveType.INT32,
        8: self.PrimitiveType.INT64,
    }
    primitive = size_to_type.get(size, self.PrimitiveType.INT32)
    return create_primitive_type(self, primitive)


def _get_operand_size(self: Any, operand: str) -> int:
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

