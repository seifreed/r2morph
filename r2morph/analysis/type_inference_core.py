"""Core type inference helpers."""

from __future__ import annotations

from typing import Any

from r2morph.core.binary import Binary

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
    for name, type_info, offset in fields:
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


def infer_type(self: Any, binary: Binary, address: int) -> Any:
    """Infer the type at a given address."""
    if address in self._address_types:
        return self._address_types[address]

    disasm = binary.get_function_disasm(address)
    if not disasm:
        return self.TypeInfo(
            type_id=self._new_type_id(),
            category=self.TypeCategory.UNKNOWN,
            confidence=0.0,
        )

    for insn in disasm:
        if insn.get("offset", 0) == address:
            return _infer_from_instruction(self, binary, insn)

    return self.TypeInfo(
        type_id=self._new_type_id(),
        category=self.TypeCategory.UNKNOWN,
        confidence=0.0,
    )


def _infer_from_instruction(self: Any, binary: Binary, insn: dict) -> Any:
    """Infer type from an instruction."""
    disasm = insn.get("disasm", "").lower()

    if "mov" in disasm:
        return _infer_from_mov(self, binary, insn, disasm)
    elif "lea" in disasm:
        return create_pointer_type(self)
    elif "cmp" in disasm or "test" in disasm:
        return create_primitive_type(self, self.PrimitiveType.BOOL)
    elif any(x in disasm for x in ["add", "sub", "imul", "mul"]):
        return _infer_arithmetic_type(self, binary, insn, disasm)
    elif any(x in disasm for x in ["xmm", "ymm", "zmm"]):
        return create_primitive_type(self, self.PrimitiveType.FLOAT64)

    return self.TypeInfo(
        type_id=self._new_type_id(),
        category=self.TypeCategory.UNKNOWN,
        confidence=0.0,
    )


def _infer_from_mov(self: Any, binary: Binary, insn: dict, disasm: str) -> Any:
    """Infer type from mov instruction."""
    parts = disasm.split(None, 1)
    if len(parts) < 2:
        return self.TypeInfo(
            type_id=self._new_type_id(),
            category=self.TypeCategory.UNKNOWN,
        )

    operands = parts[1].split(",")
    if len(operands) < 2:
        return self.TypeInfo(
            type_id=self._new_type_id(),
            category=self.TypeCategory.UNKNOWN,
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

    return self.TypeInfo(
        type_id=self._new_type_id(),
        category=self.TypeCategory.UNKNOWN,
    )


def _infer_arithmetic_type(self: Any, binary: Binary, insn: dict, disasm: str) -> Any:
    """Infer type from arithmetic instruction."""
    operand_size = _extract_operand_size(disasm)
    return _create_int_type(self, operand_size)


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


def propagate_types(self: Any, binary: Binary, func_addr: int) -> dict[int, Any]:
    """Propagate types through a function."""
    types: dict[int, Any] = {}

    disasm = binary.get_function_disasm(func_addr)
    if not disasm:
        return types

    for insn in disasm:
        addr = insn.get("offset", 0)
        type_info = _infer_from_instruction(self, binary, insn)
        if type_info.category != self.TypeCategory.UNKNOWN:
            types[addr] = type_info

    _propagate_through_phis(self, types)
    _refine_types(self, types)

    return types


def _propagate_through_phis(self: Any, types: dict[int, Any]) -> None:
    """Propagate types through phi-like constructs."""
    if not types:
        return

    _unify_adjacent_types(self, types)
    _promote_pointer_neighbors(self, types)


def _unify_adjacent_types(self: Any, types: dict[int, Any]) -> None:
    """Unify the types of values at adjacent (sorted) addresses."""
    addr_list = sorted(types.keys())

    for i in range(1, len(addr_list)):
        prev_addr = addr_list[i - 1]
        curr_addr = addr_list[i]

        prev_type = types[prev_addr]
        curr_type = types[curr_addr]

        if prev_type.category == self.TypeCategory.UNKNOWN or curr_type.category == self.TypeCategory.UNKNOWN:
            continue

        if (
            prev_type.category == curr_type.category
            and prev_type.size == curr_type.size
            and prev_type.confidence > curr_type.confidence
        ):
            types[curr_addr] = self.TypeInfo(
                type_id=curr_type.type_id,
                category=curr_type.category,
                size=curr_type.size,
                alignment=max(prev_type.alignment, curr_type.alignment),
                primitive=prev_type.primitive if prev_type.primitive else curr_type.primitive,
                confidence=(prev_type.confidence + curr_type.confidence) / 2,
            )

        if (
            curr_type.category == self.TypeCategory.POINTER
            and prev_type.category == self.TypeCategory.PRIMITIVE
            and prev_type.primitive in (self.PrimitiveType.UINT64, self.PrimitiveType.INT64)
        ):
            types[curr_addr] = self.TypeInfo(
                type_id=curr_type.type_id,
                category=self.TypeCategory.POINTER,
                size=8,
                alignment=8,
                confidence=max(prev_type.confidence, curr_type.confidence) * 0.9,
            )


def _promote_pointer_neighbors(self: Any, types: dict[int, Any]) -> None:
    """Promote a 64-bit integer within 32 bytes of a pointer to a pointer."""
    for addr, type_info in types.items():
        if type_info.category != self.TypeCategory.POINTER:
            continue
        for other_addr, other_type in types.items():
            if other_addr == addr:
                continue
            if other_type.primitive in (self.PrimitiveType.UINT64, self.PrimitiveType.INT64) and abs(other_addr - addr) < 32:
                types[other_addr] = self.TypeInfo(
                    type_id=other_type.type_id,
                    category=self.TypeCategory.POINTER,
                    size=8,
                    alignment=8,
                    confidence=0.7,
                )
                break


def _refine_types(self: Any, types: dict[int, Any]) -> None:
    """Refine types based on constraints."""
    if not types:
        return

    addr_list = list(types.keys())

    for i in range(len(addr_list) - 1):
        curr_addr = addr_list[i]
        next_addr = addr_list[i + 1] if i + 1 < len(addr_list) else None
        curr_type = types[curr_addr]

        if curr_type.category == self.TypeCategory.PRIMITIVE:
            _refine_primitive_to_pointer(self, types, curr_addr, curr_type, next_addr)
        elif curr_type.category == self.TypeCategory.UNKNOWN:
            _refine_unknown_type(self, types, curr_addr, curr_type)


def _refine_primitive_to_pointer(
    self: Any,
    types: dict[int, Any],
    curr_addr: int,
    curr_type: Any,
    next_addr: int | None,
) -> None:
    """Reinterpret a 64-bit integer as a pointer when the value 8 bytes later is a small primitive."""
    if not (curr_type.size == 8 and curr_type.primitive in (self.PrimitiveType.INT64, self.PrimitiveType.UINT64)):
        return
    if not (next_addr and (next_addr - curr_addr) == 8):
        return
    next_type = types[next_addr]
    if next_type.category == self.TypeCategory.PRIMITIVE and next_type.size <= 4:
        types[curr_addr] = self.TypeInfo(
            type_id=curr_type.type_id,
            category=self.TypeCategory.POINTER,
            size=8,
            alignment=8,
            confidence=curr_type.confidence * 0.8,
        )


def _refine_unknown_type(
    self: Any,
    types: dict[int, Any],
    curr_addr: int,
    curr_type: Any,
) -> None:
    """Assume an unknown 8-byte value is a pointer and an unknown 4-byte value a 32-bit integer."""
    if curr_type.size == 8:
        types[curr_addr] = self.TypeInfo(
            type_id=curr_type.type_id,
            category=self.TypeCategory.POINTER,
            size=8,
            alignment=8,
            confidence=0.5,
        )
    elif curr_type.size == 4:
        types[curr_addr] = self.TypeInfo(
            type_id=curr_type.type_id,
            category=self.TypeCategory.PRIMITIVE,
            size=4,
            alignment=4,
            primitive=self.PrimitiveType.INT32,
            confidence=0.5,
        )
