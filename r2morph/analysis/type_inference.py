"""
Type inference engine for binary analysis.

Provides type analysis capabilities:
- Type propagation
- Pointer alias analysis
- Struct layout inference
- Array bounds detection
"""

import copy
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.analysis.pointer_analysis import PointerAnalysis as _PointerAnalysis
from r2morph.analysis.type_inference_arm import (
    get_arm_register_aliases,
)
from r2morph.analysis.type_inference_arm import (
    infer_arm32_register_types as _infer_arm32_register_types_impl,
)
from r2morph.analysis.type_inference_arm import (
    infer_arm64_register_types as _infer_arm64_register_types_impl,
)
from r2morph.analysis.type_inference_arm import (
    infer_arm_register_types as _infer_arm_register_types_impl,
)
from r2morph.analysis.type_inference_arm import (
    propagate_arm_aliases as _propagate_arm_aliases_impl,
)
from r2morph.analysis.type_inference_core import (
    _create_int_type as _create_int_type_impl,
)
from r2morph.analysis.type_inference_core import (
    _extract_operand_size as _extract_operand_size_impl,
)
from r2morph.analysis.type_inference_core import (
    _get_operand_size as _get_operand_size_impl,
)
from r2morph.analysis.type_inference_core import (
    _infer_arithmetic_type as _infer_arithmetic_type_impl,
)
from r2morph.analysis.type_inference_core import (
    _infer_from_instruction as _infer_from_instruction_impl,
)
from r2morph.analysis.type_inference_core import (
    _infer_from_mov as _infer_from_mov_impl,
)
from r2morph.analysis.type_inference_core import (
    _promote_pointer_neighbors as _promote_pointer_neighbors_impl,
)
from r2morph.analysis.type_inference_core import (
    _propagate_through_phis as _propagate_through_phis_impl,
)
from r2morph.analysis.type_inference_core import (
    _refine_primitive_to_pointer as _refine_primitive_to_pointer_impl,
)
from r2morph.analysis.type_inference_core import (
    _refine_types as _refine_types_impl,
)
from r2morph.analysis.type_inference_core import (
    _refine_unknown_type as _refine_unknown_type_impl,
)
from r2morph.analysis.type_inference_core import (
    _unify_adjacent_types as _unify_adjacent_types_impl,
)
from r2morph.analysis.type_inference_core import (
    create_array_type as _create_array_type_impl,
)
from r2morph.analysis.type_inference_core import (
    create_pointer_type as _create_pointer_type_impl,
)
from r2morph.analysis.type_inference_core import (
    create_primitive_type as _create_primitive_type_impl,
)
from r2morph.analysis.type_inference_core import (
    create_struct_type as _create_struct_type_impl,
)
from r2morph.analysis.type_inference_core import (
    infer_type as _infer_type_impl,
)
from r2morph.analysis.type_inference_core import (
    propagate_types as _propagate_types_impl,
)
from r2morph.analysis.type_inference_queries import (
    get_struct_layout as _get_struct_layout_impl,
)
from r2morph.analysis.type_inference_queries import (
    get_value_range as _get_value_range_impl,
)
from r2morph.analysis.type_inference_queries import (
    infer_access_type as _infer_access_type_impl,
)
from r2morph.analysis.type_inference_queries import (
    is_safe_to_mutate as _is_safe_to_mutate_impl,
)
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)

PointerAnalysis = _PointerAnalysis

# Calling-convention register sets keyed by architecture. _get_calling_convention
# selects one of these and returns a fresh copy so callers never share mutable
# state. Keys: param_registers (arg-passing order), return_register, callee_saved,
# caller_saved; the 32-bit x86 cdecl entry additionally carries stack_params.
_SYSV_AMD64_CONVENTION: dict[str, Any] = {
    "param_registers": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "return_register": "rax",
    "callee_saved": ["rbx", "rbp", "r12", "r13", "r14", "r15"],
    "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
}

_CDECL_X86_32_CONVENTION: dict[str, Any] = {
    "param_registers": [],
    "return_register": "eax",
    "callee_saved": ["ebx", "esi", "edi", "ebp"],
    "caller_saved": ["eax", "ecx", "edx"],
    "stack_params": True,
}

_AAPCS_ARM32_CONVENTION: dict[str, Any] = {
    "param_registers": ["r0", "r1", "r2", "r3"],
    "return_register": "r0",
    "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
    "caller_saved": ["r0", "r1", "r2", "r3", "r12", "lr"],
}

_AAPCS64_ARM64_CONVENTION: dict[str, Any] = {
    "param_registers": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "return_register": "x0",
    "callee_saved": [
        "x19",
        "x20",
        "x21",
        "x22",
        "x23",
        "x24",
        "x25",
        "x26",
        "x27",
        "x28",
    ],
    "caller_saved": [
        "x0",
        "x1",
        "x2",
        "x3",
        "x4",
        "x5",
        "x6",
        "x7",
        "x8",
        "x9",
        "x10",
        "x11",
        "x12",
        "x13",
        "x14",
        "x15",
        "x16",
        "x17",
        "x18",
    ],
}

_EMPTY_CONVENTION: dict[str, Any] = {
    "param_registers": [],
    "return_register": "",
    "callee_saved": [],
    "caller_saved": [],
}


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
    """
    Represents type information for a value or location.

    Attributes:
        type_id: Unique identifier for this type
        category: Category of the type
        size: Size in bytes
        alignment: Alignment requirement
        primitive: Primitive type if applicable
        pointee: Type being pointed to (for pointers)
        element_type: Element type (for arrays)
        element_count: Number of elements (for arrays)
        fields: Struct fields (for structs)
        signature: Function signature (for functions)
        confidence: Confidence level (0.0-1.0)
    """

    type_id: int = 0
    category: TypeCategory = TypeCategory.UNKNOWN
    size: int = 0
    alignment: int = 1
    primitive: PrimitiveType | None = None
    pointee: "TypeInfo | None" = None
    element_type: "TypeInfo | None" = None
    element_count: int = 0
    fields: list[tuple[str, "TypeInfo", int]] = field(default_factory=list)
    signature: tuple[list["TypeInfo"], "TypeInfo"] | None = None
    confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        if self.category == TypeCategory.PRIMITIVE:
            return f"<TypeInfo {self.primitive.value if self.primitive else 'unknown'}>"
        elif self.category == TypeCategory.POINTER:
            return f"<TypeInfo {self.pointee}*>" if self.pointee else "<TypeInfo void*>"
        elif self.category == TypeCategory.ARRAY:
            return f"<TypeInfo {self.element_type}[{self.element_count}]>"
        elif self.category == TypeCategory.STRUCT:
            return f"<TypeInfo struct({len(self.fields)} fields)>"
        elif self.category == TypeCategory.FUNCTION:
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

    def get_deref_type(self) -> "TypeInfo | None":
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
    source: str  # "propagation", "pattern", "heuristic"
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:x}",
            "type": self.type_info.to_dict(),
            "source": self.source,
            "evidence": self.evidence,
        }


class TypeInference:
    """
    Type inference engine for binary analysis.

    Infers types from:
    - Instruction patterns
    - Register usage
    - Memory access patterns
    - Function signatures
    - Data structure patterns

    Usage:
        inferrer = TypeInference()
        type_info = inferrer.infer_type(binary, address)
        types = inferrer.propagate_types(binary, function)
    """

    TypeInfo = TypeInfo
    TypeCategory = TypeCategory
    PrimitiveType = PrimitiveType

    def __init__(self) -> None:
        self._type_counter: int = 0
        self._type_cache: dict[int, TypeInfo] = {}
        self._address_types: dict[int, TypeInfo] = {}
        self._register_types: dict[str, TypeInfo] = {}

    def _new_type_id(self) -> int:
        """Generate a new type ID."""
        self._type_counter += 1
        return int(self._type_counter)

    def create_primitive_type(self, primitive: PrimitiveType) -> TypeInfo:
        """Create a primitive type."""
        return _create_primitive_type_impl(self, primitive)

    def create_pointer_type(self, pointee: TypeInfo | None = None) -> TypeInfo:
        """Create a pointer type."""
        return _create_pointer_type_impl(self, pointee)

    def create_array_type(self, element_type: TypeInfo, count: int) -> TypeInfo:
        """Create an array type."""
        return _create_array_type_impl(self, element_type, count)

    def create_struct_type(self, fields: list[tuple[str, TypeInfo, int]]) -> TypeInfo:
        """Create a struct type."""
        return _create_struct_type_impl(self, fields)

    def infer_type(self, binary: Binary, address: int) -> TypeInfo:
        """
        Infer the type at a given address.

        Args:
            binary: The binary being analyzed
            address: Address to infer type for

        Returns:
            TypeInfo for the address
        """
        return _infer_type_impl(self, binary, address)

    def _infer_from_instruction(self, binary: Binary, insn: dict) -> TypeInfo:
        """Infer type from an instruction."""
        return _infer_from_instruction_impl(self, binary, insn)

    def _infer_from_mov(self, binary: Binary, insn: dict, disasm: str) -> TypeInfo:
        """Infer type from mov instruction."""
        return _infer_from_mov_impl(self, binary, insn, disasm)

    def _infer_arithmetic_type(self, binary: Binary, insn: dict, disasm: str) -> TypeInfo:
        """Infer type from arithmetic instruction."""
        return _infer_arithmetic_type_impl(self, binary, insn, disasm)

    def _create_int_type(self, size: int) -> TypeInfo:
        """Create an integer type of given size."""
        return _create_int_type_impl(self, size)

    def _get_operand_size(self, operand: str) -> int:
        """Get the size of an operand based on register name."""
        return _get_operand_size_impl(self, operand)

    def _extract_operand_size(self, disasm: str) -> int:
        """Extract operand size from instruction."""
        return _extract_operand_size_impl(disasm)

    def propagate_types(self, binary: Binary, func_addr: int) -> dict[int, TypeInfo]:
        """
        Propagate types through a function.

        Args:
            binary: The binary being analyzed
            func_addr: Function address

        Returns:
            Dictionary mapping addresses to TypeInfo
        """
        return _propagate_types_impl(self, binary, func_addr)

    def _propagate_through_phis(self, types: dict[int, TypeInfo]) -> None:
        """
        Propagate types through phi-like constructs.

        At control flow merge points (basic block entries), the types of
        incoming values need to be unified. This implements a simplified
        SSA-style type propagation.

        Args:
            types: Dictionary mapping addresses to TypeInfo (modified in place)
        """
        _propagate_through_phis_impl(self, types)

    def _unify_adjacent_types(self, types: dict[int, TypeInfo]) -> None:
        """Unify the types of values at adjacent (sorted) addresses.

        Where two neighbours share a category and size, the higher-confidence
        type wins (merging alignment/primitive/confidence); a pointer that
        follows a 64-bit integer is re-confidenced.
        """
        _unify_adjacent_types_impl(self, types)

    def _promote_pointer_neighbors(self, types: dict[int, TypeInfo]) -> None:
        """Promote a 64-bit integer within 32 bytes of a pointer to a pointer."""
        _promote_pointer_neighbors_impl(self, types)

    def _refine_types(self, types: dict[int, TypeInfo]) -> None:
        """
        Refine types based on constraints.

        Uses heuristics and constraint patterns to narrow down type information:
        - Values used in pointer arithmetic are likely pointers
        - Values used in comparisons with 0 could be pointers or integers
        - Values loaded from memory could be pointers

        Args:
            types: Dictionary mapping addresses to TypeInfo (modified in place)
        """
        _refine_types_impl(self, types)

    def _refine_primitive_to_pointer(
        self,
        types: dict[int, TypeInfo],
        curr_addr: int,
        curr_type: TypeInfo,
        next_addr: int | None,
    ) -> None:
        """Reinterpret a 64-bit integer as a pointer when the value 8 bytes
        later is a small (<=4-byte) primitive."""
        _refine_primitive_to_pointer_impl(self, types, curr_addr, curr_type, next_addr)

    def _refine_unknown_type(
        self,
        types: dict[int, TypeInfo],
        curr_addr: int,
        curr_type: TypeInfo,
    ) -> None:
        """Assume an unknown 8-byte value is a pointer and an unknown 4-byte
        value a 32-bit integer."""
        _refine_unknown_type_impl(self, types, curr_addr, curr_type)

    def propagate_interprocedural_types(
        self,
        binary: Binary,
        call_graph: dict[int, list[int]] | None = None,
    ) -> dict[int, dict[str, TypeInfo]]:
        """
        Propagate types across function boundaries using call graph.

        Uses calling convention information to track how types flow
        between functions through registers and stack.

        Args:
            binary: The binary being analyzed
            call_graph: Dict mapping function address to list of callee addresses

        Returns:
            Dictionary mapping function addresses to their parameter/return types
        """
        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "x86").lower()
        bits = arch_info.get("bits", 64)
        calling_convention = self._get_calling_convention(arch, bits)

        function_types = self._infer_all_function_param_types(binary, calling_convention)

        if call_graph:
            self._propagate_through_calls(binary, call_graph, function_types, calling_convention)

        return function_types

    def _infer_all_function_param_types(
        self,
        binary: Binary,
        calling_convention: dict[str, Any],
    ) -> dict[int, dict[str, TypeInfo]]:
        """Infer parameter types for every function, isolating per-function
        disassembly failures so one bad function never aborts the others."""
        function_types: dict[int, dict[str, TypeInfo]] = {}

        for func in binary.get_functions():
            func_addr = func.get("offset", func.get("addr", 0))
            func_name = func.get("name", f"func_{func_addr:x}")

            param_types: dict[str, TypeInfo] = {}
            try:
                disasm = binary.get_function_disasm(func_addr)
                if disasm:
                    param_types = self._infer_function_params(binary, func_addr, disasm, calling_convention)
            except Exception as e:
                logger.debug(f"Failed to infer params for {func_name}: {e}")

            function_types[func_addr] = param_types

        return function_types

    def _get_calling_convention(self, arch: str, bits: int) -> dict[str, Any]:
        """Get calling convention registers for architecture.

        Returns an independent copy so callers may read or mutate the result
        without affecting the shared convention tables or each other.
        """
        if arch in ("x86", "amd64", "x86_64"):
            convention = _SYSV_AMD64_CONVENTION if bits == 64 else _CDECL_X86_32_CONVENTION
        elif arch in ("arm", "arm32"):
            convention = _AAPCS_ARM32_CONVENTION
        elif arch in ("arm64", "aarch64"):
            convention = _AAPCS64_ARM64_CONVENTION
        else:
            convention = _EMPTY_CONVENTION

        return copy.deepcopy(convention)

    def _infer_function_params(
        self,
        binary: Binary,
        func_addr: int,
        disasm: list[dict],
        calling_conv: dict[str, Any],
    ) -> dict[str, TypeInfo]:
        """Infer function parameter types from disassembly."""
        param_types: dict[str, TypeInfo] = {}
        param_regs = calling_conv.get("param_registers", [])

        for insn in disasm[:20]:
            disasm_str = insn.get("disasm", "").lower()

            for i, reg in enumerate(param_regs):
                reg_lower = reg.lower()
                if reg_lower in disasm_str:
                    if "mov" in disasm_str and "mem" not in disasm_str:
                        param_types[f"param_{i}"] = self.create_primitive_type(PrimitiveType.INT64)
                    elif "ldr" in disasm_str or "mov" in disasm_str:
                        param_types[f"param_{i}"] = self.create_pointer_type()

        return param_types

    def _propagate_through_calls(
        self,
        binary: Binary,
        call_graph: dict[int, list[int]],
        function_types: dict[int, dict[str, TypeInfo]],
        calling_conv: dict[str, Any],
    ) -> None:
        """Propagate type information through call graph edges."""
        calling_conv.get("return_register", "")

        for caller_addr, callees in call_graph.items():
            caller_types = function_types.get(caller_addr, {})

            for callee_addr in callees:
                callee_types = function_types.get(callee_addr, {})

                for param_name, param_type in callee_types.items():
                    if param_name not in caller_types:
                        caller_types[param_name] = param_type

        for func_addr, types in function_types.items():
            self._address_types.update({func_addr + i: t for i, (n, t) in enumerate(types.items())})

    def infer_arm_register_types(
        self,
        binary: Binary,
        func_addr: int,
        disasm: list[dict],
    ) -> dict[str, TypeInfo]:
        """
        Infer types for ARM registers in a function.

        ARM-specific type inference that handles:
        - Vector registers (V0-V31 / D0-D31 / S0-S31)
        - General purpose registers with aliases
        - Condition flags and their implications

        Args:
            binary: The binary being analyzed
            func_addr: Function address
            disasm: Disassembly of the function

        Returns:
            Dictionary mapping register names to TypeInfo
        """
        return _infer_arm_register_types_impl(self, binary, func_addr, disasm, PrimitiveType)

    def _get_arm_register_aliases(self, arch: str, bits: int) -> dict[str, list[str]]:
        """Get ARM register alias mappings."""
        return get_arm_register_aliases(arch, bits)

    def _infer_arm64_register_types(
        self,
        disasm_str: str,
        register_types: dict[str, TypeInfo],
    ) -> None:
        """Infer types for ARM64 registers from instruction."""
        _infer_arm64_register_types_impl(self, disasm_str, register_types, PrimitiveType)

    def _infer_arm32_register_types(
        self,
        disasm_str: str,
        register_types: dict[str, TypeInfo],
    ) -> None:
        """Infer types for ARM32 registers from instruction."""
        _infer_arm32_register_types_impl(self, disasm_str, register_types, PrimitiveType)

    def _propagate_arm_aliases(
        self,
        register_types: dict[str, TypeInfo],
        aliases: dict[str, list[str]],
    ) -> None:
        """Propagate type information through register aliases."""
        _propagate_arm_aliases_impl(register_types, aliases)

    def get_struct_layout(self, binary: Binary, address: int) -> list[StructField] | None:
        """
        Infer struct layout from access patterns.

        Args:
            binary: The binary being analyzed
            address: Address of the struct

        Returns:
            List of StructField if struct is detected, None otherwise
        """
        return _get_struct_layout_impl(self, binary, address)

    def _infer_access_type(self, binary: Binary, xref: dict) -> TypeInfo | None:
        """Infer the type of a memory access."""
        return _infer_access_type_impl(self, binary, xref)

    def get_value_range(self, binary: Binary, address: int) -> tuple[int, int] | None:
        """
        Get the possible value range at an address.

        Args:
            binary: The binary being analyzed
            address: Address to analyze

        Returns:
            Tuple of (min, max) if determinable, None otherwise
        """
        type_info = self.infer_type(binary, address)
        return _get_value_range_impl(type_info)

    def is_safe_to_mutate(self, binary: Binary, address: int, mutation_type: str) -> tuple[bool, str]:
        """
        Check if it's safe to apply a mutation at an address.

        Args:
            binary: The binary being analyzed
            address: Address to check
            mutation_type: Type of mutation to apply

        Returns:
            Tuple of (is_safe, reason)
        """
        type_info = self.infer_type(binary, address)
        return _is_safe_to_mutate_impl(type_info, mutation_type)


def infer_type(binary: Binary, address: int) -> TypeInfo:
    """
    Convenience function to infer type at an address.

    Args:
        binary: The binary being analyzed
        address: Address to infer type for

    Returns:
        TypeInfo for the address
    """
    inferrer = TypeInference()
    return inferrer.infer_type(binary, address)


def propagate_types(binary: Binary, func_addr: int) -> dict[int, TypeInfo]:
    """
    Convenience function to propagate types through a function.

    Args:
        binary: The binary being analyzed
        func_addr: Function address

    Returns:
        Dictionary mapping addresses to TypeInfo
    """
    inferrer = TypeInference()
    return inferrer.propagate_types(binary, func_addr)
