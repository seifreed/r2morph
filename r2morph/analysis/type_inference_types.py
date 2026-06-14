"""Type inference data model and calling-convention tables."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.analysis import type_inference_conventions as _type_inference_conventions

_SYSV_AMD64_CONVENTION = _type_inference_conventions._SYSV_AMD64_CONVENTION
_CDECL_X86_32_CONVENTION = _type_inference_conventions._CDECL_X86_32_CONVENTION
_AAPCS_ARM32_CONVENTION = _type_inference_conventions._AAPCS_ARM32_CONVENTION
_AAPCS64_ARM64_CONVENTION = _type_inference_conventions._AAPCS64_ARM64_CONVENTION
_EMPTY_CONVENTION = _type_inference_conventions._EMPTY_CONVENTION


class TypeCategory(Enum):
    """Category of a type."""

    PRIMITIVE = "primitive"
    POINTER = "pointer"
    ARRAY = "array"
    STRUCT = "struct"
    FUNCTION = "function"
    UNKNOWN = "unknown"


class PrimitiveType(Enum):
    """Primitive types."""

    INT8 = "int8"
    INT16 = "int16"
    INT32 = "int32"
    INT64 = "int64"
    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT32 = "uint32"
    UINT64 = "uint64"
    FLOAT32 = "float32"
    FLOAT64 = "float64"
    BOOL = "bool"
    VOID = "void"


@dataclass
class TypeInfo:
    """Represents type information for a value or location."""

    type_id: int = 0
    category: TypeCategory = TypeCategory.UNKNOWN
    size: int = 0
    alignment: int = 1
    primitive: PrimitiveType | None = None
    pointee: TypeInfo | None = None
    element_type: TypeInfo | None = None
    element_count: int = 0
    fields: list[tuple[str, TypeInfo, int]] = field(default_factory=list)
    signature: tuple[list[TypeInfo], TypeInfo] | None = None
    confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        if self.category == TypeCategory.PRIMITIVE:
            return f"<TypeInfo {self.primitive.value if self.primitive else 'unknown'}>"
        if self.category == TypeCategory.POINTER:
            return f"<TypeInfo {self.pointee}*>" if self.pointee else "<TypeInfo void*>"
        if self.category == TypeCategory.ARRAY:
            return f"<TypeInfo {self.element_type}[{self.element_count}]>"
        if self.category == TypeCategory.STRUCT:
            return f"<TypeInfo struct({len(self.fields)} fields)>"
        if self.category == TypeCategory.FUNCTION:
            return "<TypeInfo function>"
        return f"<TypeInfo {self.category.value}>"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type_id": self.type_id,
            "category": self.category.value,
            "size": self.size,
            "alignment": self.alignment,
            "primitive": self.primitive.value if self.primitive else None,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    def is_pointer(self) -> bool:
        """Check if this is a pointer type."""
        return self.category == TypeCategory.POINTER

    def is_array(self) -> bool:
        """Check if this is an array type."""
        return self.category == TypeCategory.ARRAY

    def is_struct(self) -> bool:
        """Check if this is a struct type."""
        return self.category == TypeCategory.STRUCT

    def is_primitive(self) -> bool:
        """Check if this is a primitive type."""
        return self.category == TypeCategory.PRIMITIVE

    def is_integer(self) -> bool:
        """Check if this is an integer type."""
        if self.category != TypeCategory.PRIMITIVE:
            return False
        return self.primitive in (
            PrimitiveType.INT8,
            PrimitiveType.INT16,
            PrimitiveType.INT32,
            PrimitiveType.INT64,
            PrimitiveType.UINT8,
            PrimitiveType.UINT16,
            PrimitiveType.UINT32,
            PrimitiveType.UINT64,
        )

    def is_float(self) -> bool:
        """Check if this is a floating point type."""
        if self.category != TypeCategory.PRIMITIVE:
            return False
        return self.primitive in (PrimitiveType.FLOAT32, PrimitiveType.FLOAT64)

    def get_deref_type(self) -> TypeInfo | None:
        """Get the type when dereferenced."""
        if self.category == TypeCategory.POINTER:
            return self.pointee
        if self.category == TypeCategory.ARRAY:
            return self.element_type
        return None


@dataclass
class StructField:
    """Represents a field in a struct."""

    name: str
    offset: int
    type_info: TypeInfo
    size: int = 0

    def __post_init__(self) -> None:
        if self.size == 0:
            self.size = self.type_info.size


@dataclass
class TypeInferenceResult:
    """Result of type inference analysis."""

    address: int
    type_info: TypeInfo
    source: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:x}",
            "type": self.type_info.to_dict(),
            "source": self.source,
            "evidence": self.evidence,
        }
