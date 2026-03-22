"""
Type inference engine for binary analysis.

Provides type analysis capabilities:
- Type propagation
- Pointer alias analysis
- Struct layout inference
- Array bounds detection
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


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
            return f"<TypeInfo function>"
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

    def __post_init__(self):
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

    def __init__(self):
        self._type_counter = 0
        self._type_cache: dict[int, TypeInfo] = {}
        self._address_types: dict[int, TypeInfo] = {}
        self._register_types: dict[str, TypeInfo] = {}

    def _new_type_id(self) -> int:
        """Generate a new type ID."""
        self._type_counter += 1
        return self._type_counter

    def create_primitive_type(self, primitive: PrimitiveType) -> TypeInfo:
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

    def create_pointer_type(self, pointee: TypeInfo | None = None) -> TypeInfo:
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

    def create_array_type(self, element_type: TypeInfo, count: int) -> TypeInfo:
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

    def create_struct_type(self, fields: list[tuple[str, TypeInfo, int]]) -> TypeInfo:
        """Create a struct type."""
        total_size = 0
        max_alignment = 1
        for name, type_info, offset in fields:
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

    def infer_type(self, binary: Binary, address: int) -> TypeInfo:
        """
        Infer the type at a given address.

        Args:
            binary: The binary being analyzed
            address: Address to infer type for

        Returns:
            TypeInfo for the address
        """
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
                return self._infer_from_instruction(binary, insn)

        return TypeInfo(
            type_id=self._new_type_id(),
            category=TypeCategory.UNKNOWN,
            confidence=0.0,
        )

    def _infer_from_instruction(self, binary: Binary, insn: dict) -> TypeInfo:
        """Infer type from an instruction."""
        disasm = insn.get("disasm", "").lower()

        if "mov" in disasm:
            return self._infer_from_mov(binary, insn, disasm)
        elif "lea" in disasm:
            return self.create_pointer_type()
        elif "cmp" in disasm or "test" in disasm:
            return self.create_primitive_type(PrimitiveType.BOOL)
        elif any(x in disasm for x in ["add", "sub", "imul", "mul"]):
            return self._infer_arithmetic_type(binary, insn, disasm)
        elif any(x in disasm for x in ["xmm", "ymm", "zmm"]):
            return self.create_primitive_type(PrimitiveType.FLOAT64)

        return TypeInfo(
            type_id=self._new_type_id(),
            category=TypeCategory.UNKNOWN,
            confidence=0.0,
        )

    def _infer_from_mov(self, binary: Binary, insn: dict, disasm: str) -> TypeInfo:
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
            size = self._get_operand_size(dest)
            return self._create_int_type(size)

        if src.startswith("["):
            return self.create_pointer_type()

        if "[" in dest:
            ptr_size = 8
            return self.create_pointer_type()

        return TypeInfo(
            type_id=self._new_type_id(),
            category=TypeCategory.UNKNOWN,
        )

    def _infer_arithmetic_type(self, binary: Binary, insn: dict, disasm: str) -> TypeInfo:
        """Infer type from arithmetic instruction."""
        operand_size = self._extract_operand_size(disasm)
        return self._create_int_type(operand_size)

    def _create_int_type(self, size: int) -> TypeInfo:
        """Create an integer type of given size."""
        size_to_type = {
            1: PrimitiveType.INT8,
            2: PrimitiveType.INT16,
            4: PrimitiveType.INT32,
            8: PrimitiveType.INT64,
        }
        primitive = size_to_type.get(size, PrimitiveType.INT32)
        return self.create_primitive_type(primitive)

    def _get_operand_size(self, operand: str) -> int:
        """Get the size of an operand based on register name."""
        operand = operand.lower().strip()

        size_map = {
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

        for reg, size in size_map.items():
            if operand.startswith(reg):
                return size

        return 4

    def _extract_operand_size(self, disasm: str) -> int:
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

    def propagate_types(self, binary: Binary, func_addr: int) -> dict[int, TypeInfo]:
        """
        Propagate types through a function.

        Args:
            binary: The binary being analyzed
            func_addr: Function address

        Returns:
            Dictionary mapping addresses to TypeInfo
        """
        types: dict[int, TypeInfo] = {}

        disasm = binary.get_function_disasm(func_addr)
        if not disasm:
            return types

        for insn in disasm:
            addr = insn.get("offset", 0)
            type_info = self._infer_from_instruction(binary, insn)
            if type_info.category != TypeCategory.UNKNOWN:
                types[addr] = type_info

        self._propagate_through_phis(types)
        self._refine_types(types)

        return types

    def _propagate_through_phis(self, types: dict[int, TypeInfo]) -> None:
        """
        Propagate types through phi-like constructs.

        At control flow merge points (basic block entries), the types of
        incoming values need to be unified. This implements a simplified
        SSA-style type propagation.

        Args:
            types: Dictionary mapping addresses to TypeInfo (modified in place)
        """
        if not types:
            return

        addr_list = sorted(types.keys())

        for i in range(1, len(addr_list)):
            prev_addr = addr_list[i - 1]
            curr_addr = addr_list[i]

            prev_type = types[prev_addr]
            curr_type = types[curr_addr]

            if prev_type.category == TypeCategory.UNKNOWN or curr_type.category == TypeCategory.UNKNOWN:
                continue

            if prev_type.category == curr_type.category:
                if prev_type.size == curr_type.size:
                    if prev_type.confidence > curr_type.confidence:
                        types[curr_addr] = TypeInfo(
                            type_id=curr_type.type_id,
                            category=curr_type.category,
                            size=curr_type.size,
                            alignment=max(prev_type.alignment, curr_type.alignment),
                            primitive=prev_type.primitive if prev_type.primitive else curr_type.primitive,
                            confidence=(prev_type.confidence + curr_type.confidence) / 2,
                        )

            if curr_type.category == TypeCategory.POINTER and prev_type.category == TypeCategory.PRIMITIVE:
                if prev_type.primitive in (PrimitiveType.UINT64, PrimitiveType.INT64):
                    types[curr_addr] = TypeInfo(
                        type_id=curr_type.type_id,
                        category=TypeCategory.POINTER,
                        size=8,
                        alignment=8,
                        confidence=max(prev_type.confidence, curr_type.confidence) * 0.9,
                    )

        for addr, type_info in types.items():
            if type_info.category == TypeCategory.POINTER:
                for other_addr, other_type in types.items():
                    if other_addr == addr:
                        continue
                    if other_type.primitive in (PrimitiveType.UINT64, PrimitiveType.INT64):
                        if abs(other_addr - addr) < 32:
                            types[other_addr] = TypeInfo(
                                type_id=other_type.type_id,
                                category=TypeCategory.POINTER,
                                size=8,
                                alignment=8,
                                confidence=0.7,
                            )
                            break

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
        if not types:
            return

        addr_list = list(types.keys())

        for i in range(len(addr_list) - 1):
            curr_addr = addr_list[i]
            next_addr = addr_list[i + 1] if i + 1 < len(addr_list) else None

            curr_type = types[curr_addr]

            if curr_type.category == TypeCategory.PRIMITIVE:
                if curr_type.size == 8 and curr_type.primitive in (PrimitiveType.INT64, PrimitiveType.UINT64):
                    if next_addr and (next_addr - curr_addr) == 8:
                        next_type = types[next_addr]
                        if next_type.category == TypeCategory.PRIMITIVE:
                            if next_type.size <= 4:
                                types[curr_addr] = TypeInfo(
                                    type_id=curr_type.type_id,
                                    category=TypeCategory.POINTER,
                                    size=8,
                                    alignment=8,
                                    confidence=curr_type.confidence * 0.8,
                                )

            if curr_type.category == TypeCategory.UNKNOWN:
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

        type_counts: dict[TypeCategory, int] = {}
        for type_info in types.values():
            type_counts[type_info.category] = type_counts.get(type_info.category, 0) + 1

        # NOTE: Do NOT blindly promote all 8-byte primitives to pointers.
        # Only values with evidence of pointer usage (dereferences, lea patterns)
        # should be classified as pointers. Blanket promotion causes 64-bit
        # integers to be misclassified, leading to incorrect mutation safety
        # decisions downstream.

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
        functions = binary.get_functions()
        function_types: dict[int, dict[str, TypeInfo]] = {}

        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "x86").lower()
        bits = arch_info.get("bits", 64)

        calling_convention = self._get_calling_convention(arch, bits)

        for func in functions:
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

        if call_graph:
            self._propagate_through_calls(binary, call_graph, function_types, calling_convention)

        return function_types

    def _get_calling_convention(self, arch: str, bits: int) -> dict[str, Any]:
        """Get calling convention registers for architecture."""
        if arch in ("x86", "amd64", "x86_64"):
            if bits == 64:
                return {
                    "param_registers": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
                    "return_register": "rax",
                    "callee_saved": ["rbx", "rbp", "r12", "r13", "r14", "r15"],
                    "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
                }
            else:
                return {
                    "param_registers": [],
                    "return_register": "eax",
                    "callee_saved": ["ebx", "esi", "edi", "ebp"],
                    "caller_saved": ["eax", "ecx", "edx"],
                    "stack_params": True,
                }
        elif arch in ("arm", "arm32"):
            return {
                "param_registers": ["r0", "r1", "r2", "r3"],
                "return_register": "r0",
                "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
                "caller_saved": ["r0", "r1", "r2", "r3", "r12", "lr"],
            }
        elif arch in ("arm64", "aarch64"):
            return {
                "param_registers": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
                "return_register": "x0",
                "callee_saved": ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"],
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

        return {
            "param_registers": [],
            "return_register": "",
            "callee_saved": [],
            "caller_saved": [],
        }

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
        return_reg = calling_conv.get("return_register", "")

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
        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "arm").lower()
        bits = arch_info.get("bits", 32)

        register_types: dict[str, TypeInfo] = {}

        reg_aliases = self._get_arm_register_aliases(arch, bits)

        for insn in disasm:
            disasm_str = insn.get("disasm", "").lower()

            if arch in ("arm64", "aarch64"):
                self._infer_arm64_register_types(disasm_str, register_types)
            elif arch in ("arm", "arm32"):
                self._infer_arm32_register_types(disasm_str, register_types)

        self._propagate_arm_aliases(register_types, reg_aliases)

        return register_types

    def _get_arm_register_aliases(self, arch: str, bits: int) -> dict[str, list[str]]:
        """Get ARM register alias mappings."""
        aliases: dict[str, list[str]] = {}

        if arch in ("arm64", "aarch64"):
            for i in range(32):
                aliases[f"x{i}"] = [f"w{i}", f"x{i}"]
                aliases[f"w{i}"] = [f"w{i}", f"x{i}"]

            aliases["x29"] = ["fp", "x29"]
            aliases["x30"] = ["lr", "x30"]
            aliases["sp"] = ["sp", "x31"]

            for i in range(32):
                aliases[f"v{i}.d"] = [f"d{i}", f"v{i}"]
                aliases[f"v{i}.s"] = [f"s{2 * i}", f"v{i}"]
                aliases[f"v{i}.b"] = [f"b{4 * i}", f"v{i}"]

        elif arch in ("arm", "arm32"):
            for i in range(16):
                aliases[f"r{i}"] = [f"r{i}"]

            aliases["fp"] = ["r11", "fp"]
            aliases["ip"] = ["r12", "ip"]
            aliases["sp"] = ["r13", "sp"]
            aliases["lr"] = ["r14", "lr"]
            aliases["pc"] = ["r15", "pc"]

            aliases["s0"] = ["s0", "d0_lower"]
            aliases["d0"] = ["d0", "s0", "s1"]

        return aliases

    def _infer_arm64_register_types(
        self,
        disasm_str: str,
        register_types: dict[str, TypeInfo],
    ) -> None:
        """Infer types for ARM64 registers from instruction."""
        if "ldr" in disasm_str:
            import re

            match = re.search(r"ldr\s+(\w+)", disasm_str)
            if match:
                reg = match.group(1).lower()
                if reg.startswith("x") or reg.startswith("w"):
                    register_types[reg] = self.create_pointer_type()
                elif reg.startswith("d") or reg.startswith("s"):
                    register_types[reg] = self.create_primitive_type(PrimitiveType.FLOAT64)

        elif "str" in disasm_str:
            import re

            match = re.search(r"str\s+(\w+)", disasm_str)
            if match:
                reg = match.group(1).lower()
                if reg not in register_types:
                    register_types[reg] = self.create_primitive_type(PrimitiveType.UINT64)

        elif "mov" in disasm_str:
            import re

            match = re.search(r"mov\s+(\w+)\s*,\s*(\w+)", disasm_str)
            if match:
                dest, src = match.group(1).lower(), match.group(2).lower()
                if src.startswith("#"):
                    register_types[dest] = self.create_primitive_type(PrimitiveType.INT64)
                elif src in register_types:
                    register_types[dest] = register_types[src]

        elif "fmov" in disasm_str:
            import re

            match = re.search(r"fmov\s+(\w+)", disasm_str)
            if match:
                reg = match.group(1).lower()
                register_types[reg] = self.create_primitive_type(PrimitiveType.FLOAT64)

        elif "add" in disasm_str or "sub" in disasm_str:
            import re

            match = re.search(r"(add|sub)\s+(\w+)", disasm_str)
            if match:
                reg = match.group(2).lower()
                if reg not in register_types:
                    register_types[reg] = self.create_primitive_type(PrimitiveType.INT64)

    def _infer_arm32_register_types(
        self,
        disasm_str: str,
        register_types: dict[str, TypeInfo],
    ) -> None:
        """Infer types for ARM32 registers from instruction."""
        if "ldr" in disasm_str:
            import re

            match = re.search(r"ldr\s+(\w+)", disasm_str)
            if match:
                reg = match.group(1).lower()
                if reg.startswith("r"):
                    register_types[reg] = self.create_pointer_type()
                elif reg.startswith("s"):
                    register_types[reg] = self.create_primitive_type(PrimitiveType.FLOAT32)
                elif reg.startswith("d"):
                    register_types[reg] = self.create_primitive_type(PrimitiveType.FLOAT64)

        elif "str" in disasm_str:
            import re

            match = re.search(r"str\s+(\w+)", disasm_str)
            if match:
                reg = match.group(1).lower()
                if reg not in register_types:
                    register_types[reg] = self.create_primitive_type(PrimitiveType.UINT32)

        elif "mov" in disasm_str:
            import re

            match = re.search(r"mov\s+(\w+)\s*,\s*(\w+)", disasm_str)
            if match:
                dest, src = match.group(1).lower(), match.group(2).lower()
                if src.startswith("#"):
                    register_types[dest] = self.create_primitive_type(PrimitiveType.INT32)
                elif src in register_types:
                    register_types[dest] = register_types[src]

    def _propagate_arm_aliases(
        self,
        register_types: dict[str, TypeInfo],
        aliases: dict[str, list[str]],
    ) -> None:
        """Propagate type information through register aliases."""
        for primary_reg, alias_list in aliases.items():
            if primary_reg in register_types:
                type_info = register_types[primary_reg]
                for alias in alias_list:
                    if alias not in register_types:
                        register_types[alias] = type_info

        for primary_reg, alias_list in aliases.items():
            if primary_reg not in register_types:
                for alias in alias_list:
                    if alias in register_types:
                        register_types[primary_reg] = register_types[alias]
                        break

    def get_struct_layout(self, binary: Binary, address: int) -> list[StructField] | None:
        """
        Infer struct layout from access patterns.

        Args:
            binary: The binary being analyzed
            address: Address of the struct

        Returns:
            List of StructField if struct is detected, None otherwise
        """
        fields: list[StructField] = []

        try:
            xrefs = binary.r2.cmdj(f"axtj @ {address}") if binary.r2 else []
        except Exception:
            xrefs = []

        if not xrefs:
            return None

        for xref in xrefs:
            offset = xref.get("offset", 0) if isinstance(xref, dict) else 0
            access_type = self._infer_access_type(binary, xref if isinstance(xref, dict) else {})

            if access_type:
                fields.append(
                    StructField(
                        name=f"field_{offset:x}",
                        offset=offset,
                        type_info=access_type,
                    )
                )

        fields.sort(key=lambda f: f.offset)

        return fields if fields else None

    def _infer_access_type(self, binary: Binary, xref: dict) -> TypeInfo | None:
        """Infer the type of a memory access."""
        return self.create_primitive_type(PrimitiveType.UINT64)

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

        if type_info.is_integer():
            size = type_info.size
            if size == 1:
                return (0, 255)
            if size == 2:
                return (0, 65535)
            if size == 4:
                return (0, 2**32 - 1)
            if size == 8:
                return (0, 2**64 - 1)

        return None

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

        if mutation_type == "register_substitution":
            if type_info.is_pointer():
                return (False, "Register holds pointer - unsafe to substitute")

        if mutation_type == "instruction_expansion":
            if type_info.is_pointer():
                return (False, "Pointer arithmetic - expansion may break semantics")

        return (True, "Safe to mutate")


class PointerAnalysis:
    """
    Pointer alias analysis.

    Tracks pointer aliases and points-to relationships.

    Usage:
        analysis = PointerAnalysis()
        analysis.compute_aliases(binary)
        aliases = analysis.get_aliases(address)
    """

    def __init__(self):
        self._points_to: dict[int, set[int]] = {}
        self._aliases: dict[int, set[int]] = {}

    def compute_aliases(self, binary: Binary) -> None:
        """Compute pointer alias information."""
        functions = binary.get_functions()

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            self._analyze_function_pointers(binary, func_addr)

        self._compute_transitive_aliases()

    def _analyze_function_pointers(self, binary: Binary, func_addr: int) -> None:
        """Analyze pointers in a function."""
        disasm = binary.get_function_disasm(func_addr)
        if not disasm:
            return

        for insn in disasm:
            self._extract_pointer_use(binary, insn)

    def _extract_pointer_use(self, binary: Binary, insn: dict) -> None:
        """Extract pointer use from instruction."""
        disasm = insn.get("disasm", "").lower()
        addr = insn.get("offset", 0)

        if "lea" in disasm:
            target = self._extract_lea_target(disasm)
            if target:
                if addr not in self._points_to:
                    self._points_to[addr] = set()
                self._points_to[addr].add(target)

    def _extract_lea_target(self, disasm: str) -> int | None:
        """Extract LEA target from disassembly."""
        parts = disasm.split("[")
        if len(parts) < 2:
            return None

        bracket_content = parts[1].split("]")[0]
        if bracket_content.startswith("0x"):
            try:
                return int(bracket_content, 16)
            except ValueError:
                pass

        return None

    def _compute_transitive_aliases(self) -> None:
        """Compute transitive alias closure."""
        for addr in self._points_to:
            self._aliases[addr] = set(self._points_to[addr])

        changed = True
        while changed:
            changed = False
            for addr, aliases in list(self._aliases.items()):
                new_aliases = set(aliases)
                for alias in aliases:
                    if alias in self._aliases:
                        new_aliases.update(self._aliases[alias])
                if new_aliases != aliases:
                    self._aliases[addr] = new_aliases
                    changed = True

    def get_points_to(self, address: int) -> set[int]:
        """
        Get addresses that a pointer may point to.

        Args:
            address: Address with pointer

        Returns:
            Set of possible target addresses
        """
        return self._points_to.get(address, set())

    def get_aliases(self, address: int) -> set[int]:
        """
        Get all aliases of a pointer.

        Args:
            address: Address with pointer

        Returns:
            Set of alias addresses
        """
        return self._aliases.get(address, set())

    def may_alias(self, addr1: int, addr2: int) -> bool:
        """
        Check if two pointers may alias.

        Args:
            addr1: First pointer address
            addr2: Second pointer address

        Returns:
            True if they may alias
        """
        if addr1 == addr2:
            return True

        aliases1 = self.get_aliases(addr1)
        aliases2 = self.get_aliases(addr2)

        return bool(aliases1 & aliases2)


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
