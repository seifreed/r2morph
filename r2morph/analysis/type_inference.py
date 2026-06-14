"""
Type inference engine for binary analysis.

Provides type analysis capabilities:
- Type propagation
- Pointer alias analysis
- Struct layout inference
- Array bounds detection
"""

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
from r2morph.analysis.type_inference_convention_resolver import (
    get_calling_convention as _get_calling_convention_impl,
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
from r2morph.analysis.type_inference_interprocedural import (
    _infer_all_function_param_types as _infer_all_function_param_types_impl,
)
from r2morph.analysis.type_inference_interprocedural import (
    _infer_function_params as _infer_function_params_impl,
)
from r2morph.analysis.type_inference_interprocedural import (
    _propagate_through_calls as _propagate_through_calls_impl,
)
from r2morph.analysis.type_inference_interprocedural import (
    propagate_interprocedural_types as _propagate_interprocedural_types_impl,
)
from r2morph.analysis.type_inference_queries import (
    get_struct_layout as _get_struct_layout_impl,
)
from r2morph.analysis.type_inference_queries import (
    infer_access_type as _infer_access_type_impl,
)
from r2morph.analysis.type_inference_types import PrimitiveType, StructField, TypeCategory, TypeInfo
from r2morph.analysis.type_inference_types import (
    TypeInferenceResult as _TypeInferenceResult,
)
from r2morph.analysis.type_inference_value_analysis import (
    get_value_range as _get_value_range_impl,
)
from r2morph.analysis.type_inference_value_analysis import (
    is_safe_to_mutate as _is_safe_to_mutate_impl,
)
from r2morph.core.binary import Binary

PointerAnalysis = _PointerAnalysis
TypeInferenceResult = _TypeInferenceResult


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
        return _propagate_interprocedural_types_impl(self, binary, call_graph)

    def _infer_all_function_param_types(
        self,
        binary: Binary,
        calling_convention: dict[str, Any],
    ) -> dict[int, dict[str, TypeInfo]]:
        """Infer parameter types for every function, isolating per-function
        disassembly failures so one bad function never aborts the others."""
        return _infer_all_function_param_types_impl(self, binary, calling_convention)

    def _get_calling_convention(self, arch: str, bits: int) -> dict[str, Any]:
        """Get calling convention registers for architecture.

        Returns an independent copy so callers may read or mutate the result
        without affecting the shared convention tables or each other.
        """
        return _get_calling_convention_impl(arch, bits)

    def _infer_function_params(
        self,
        binary: Binary,
        func_addr: int,
        disasm: list[dict],
        calling_conv: dict[str, Any],
    ) -> dict[str, TypeInfo]:
        """Infer function parameter types from disassembly."""
        return _infer_function_params_impl(self, binary, func_addr, disasm, calling_conv)

    def _propagate_through_calls(
        self,
        binary: Binary,
        call_graph: dict[int, list[int]],
        function_types: dict[int, dict[str, TypeInfo]],
        calling_conv: dict[str, Any],
    ) -> None:
        """Propagate type information through call graph edges."""
        _propagate_through_calls_impl(self, binary, call_graph, function_types, calling_conv)

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
