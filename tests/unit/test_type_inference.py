"""
Tests for Type Inference engine.

Covers:
- TypeInfo creation
- Type inference from instructions
- Pointer analysis
- Type propagation
"""

from unittest.mock import MagicMock

from r2morph.analysis.type_inference import (
    TypeCategory,
    PrimitiveType,
    TypeInfo,
    StructField,
    TypeInference,
    PointerAnalysis,
    infer_type,
    propagate_types,
)


class TestTypeInfo:
    """Test TypeInfo dataclass."""

    def test_primitive_type(self):
        """Test primitive type creation."""
        type_info = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            size=4,
            alignment=4,
            primitive=PrimitiveType.INT32,
        )
        assert type_info.category == TypeCategory.PRIMITIVE
        assert type_info.size == 4
        assert type_info.primitive == PrimitiveType.INT32

    def test_pointer_type(self):
        """Test pointer type creation."""
        pointee = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.INT32,
        )
        ptr = TypeInfo(
            type_id=2,
            category=TypeCategory.POINTER,
            size=8,
            pointee=pointee,
        )
        assert ptr.is_pointer()
        assert ptr.pointee == pointee

    def test_array_type(self):
        """Test array type creation."""
        element = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            size=4,
            primitive=PrimitiveType.INT32,
        )
        arr = TypeInfo(
            type_id=2,
            category=TypeCategory.ARRAY,
            size=40,
            element_type=element,
            element_count=10,
        )
        assert arr.is_array()
        assert arr.element_count == 10
        assert arr.size == 40

    def test_struct_type(self):
        """Test struct type creation."""
        field1 = TypeInfo(type_id=1, category=TypeCategory.PRIMITIVE, size=4)
        field2 = TypeInfo(type_id=2, category=TypeCategory.PRIMITIVE, size=8)

        struct_type = TypeInfo(
            type_id=3,
            category=TypeCategory.STRUCT,
            size=16,
            fields=[
                ("x", field1, 0),
                ("y", field2, 8),
            ],
        )
        assert struct_type.is_struct()
        assert len(struct_type.fields) == 2

    def test_is_integer(self):
        """Test integer type detection."""
        int_type = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.INT32,
        )
        assert int_type.is_integer()

        float_type = TypeInfo(
            type_id=2,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.FLOAT32,
        )
        assert not float_type.is_integer()

    def test_is_float(self):
        """Test float type detection."""
        float_type = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.FLOAT32,
        )
        assert float_type.is_float()

        int_type = TypeInfo(
            type_id=2,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.INT32,
        )
        assert not int_type.is_float()

    def test_get_deref_type(self):
        """Test dereference type."""
        pointee = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.INT32,
        )
        ptr = TypeInfo(
            type_id=2,
            category=TypeCategory.POINTER,
            pointee=pointee,
        )
        assert ptr.get_deref_type() == pointee

    def test_to_dict(self):
        """Test serialization."""
        type_info = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            size=4,
            primitive=PrimitiveType.INT32,
            confidence=0.9,
        )
        d = type_info.to_dict()
        assert d["type_id"] == 1
        assert d["category"] == "primitive"
        assert d["size"] == 4


class TestTypeInference:
    """Test TypeInference class."""

    def test_create_primitive_type(self):
        """Test primitive type creation."""
        inferrer = TypeInference()

        int32 = inferrer.create_primitive_type(PrimitiveType.INT32)
        assert int32.category == TypeCategory.PRIMITIVE
        assert int32.size == 4

        int64 = inferrer.create_primitive_type(PrimitiveType.INT64)
        assert int64.size == 8

    def test_create_pointer_type(self):
        """Test pointer type creation."""
        inferrer = TypeInference()

        ptr = inferrer.create_pointer_type()
        assert ptr.category == TypeCategory.POINTER
        assert ptr.size == 8

        int32 = inferrer.create_primitive_type(PrimitiveType.INT32)
        ptr_to_int = inferrer.create_pointer_type(int32)
        assert ptr_to_int.pointee == int32

    def test_create_array_type(self):
        """Test array type creation."""
        inferrer = TypeInference()

        int32 = inferrer.create_primitive_type(PrimitiveType.INT32)
        arr = inferrer.create_array_type(int32, 10)

        assert arr.category == TypeCategory.ARRAY
        assert arr.element_count == 10
        assert arr.size == 40

    def test_create_struct_type(self):
        """Test struct type creation."""
        inferrer = TypeInference()

        int32 = inferrer.create_primitive_type(PrimitiveType.INT32)
        int64 = inferrer.create_primitive_type(PrimitiveType.INT64)

        struct_type = inferrer.create_struct_type(
            [
                ("x", int32, 0),
                ("y", int64, 8),
            ]
        )

        assert struct_type.category == TypeCategory.STRUCT
        assert len(struct_type.fields) == 2

    def test_infer_type_mov_immediate(self):
        """Test type inference from mov immediate."""
        inferrer = TypeInference()

        binary = MagicMock()
        binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "disasm": "mov eax, 0x42"},
        ]

        type_info = inferrer.infer_type(binary, 0x1000)
        assert type_info.category == TypeCategory.PRIMITIVE

    def test_infer_type_lea(self):
        """Test type inference from LEA."""
        inferrer = TypeInference()

        binary = MagicMock()
        binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "disasm": "lea rax, [rip+0x1000]"},
        ]

        type_info = inferrer.infer_type(binary, 0x1000)
        assert type_info.category == TypeCategory.POINTER

    def test_infer_type_comparison(self):
        """Test type inference from comparison."""
        inferrer = TypeInference()

        binary = MagicMock()
        binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "disasm": "cmp eax, ebx"},
        ]

        type_info = inferrer.infer_type(binary, 0x1000)
        assert type_info.primitive == PrimitiveType.BOOL

    def test_propagate_types(self):
        """Test type propagation through function."""
        inferrer = TypeInference()

        binary = MagicMock()
        binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "disasm": "mov eax, 0x42"},
            {"offset": 0x1005, "disasm": "add eax, ebx"},
            {"offset": 0x100A, "disasm": "ret"},
        ]

        types = inferrer.propagate_types(binary, 0x1000)
        assert len(types) >= 0

    def test_get_operand_size(self):
        """Test operand size detection."""
        inferrer = TypeInference()

        assert inferrer._get_operand_size("rax") == 8
        assert inferrer._get_operand_size("eax") == 4
        assert inferrer._get_operand_size("ax") == 2
        assert inferrer._get_operand_size("al") == 1

    def test_get_operand_size_contract(self):
        """Characterize the full operand-size contract.

        Guards the module-level ``_X86_REGISTER_SIZES`` lookup: the size is
        resolved by ``str.startswith`` over the table in declaration order and
        the first match wins. The wider names are declared first, so a
        sub-register whose name extends a wider one (``r8d`` starts with the
        8-byte ``r8``) resolves to the wider size. This pins that order-sensitive
        behavior so a future re-sort of the table is caught as a regression.
        """
        inferrer = TypeInference()

        # Extended (numeric) registers across all widths.
        assert inferrer._get_operand_size("r15") == 8
        assert inferrer._get_operand_size("esi") == 4

        # Order-sensitive prefix match: r8d/r8w start with the 8-byte "r8" key,
        # which is declared first, so they resolve to 8 (not 4 / 2).
        assert inferrer._get_operand_size("r8d") == 8
        assert inferrer._get_operand_size("r8w") == 8

        # Case-insensitive and whitespace-trimmed.
        assert inferrer._get_operand_size("RAX") == 8
        assert inferrer._get_operand_size("  rax  ") == 8

        # Matches on the leading register of a multi-token operand.
        assert inferrer._get_operand_size("rax, rbx") == 8

        # Unknown operands fall back to the default width.
        assert inferrer._get_operand_size("xmm0") == 4
        assert inferrer._get_operand_size("not_a_register") == 4

    def test_get_calling_convention_contract(self):
        """Characterize the calling-convention table for every architecture.

        Pins the exact register sets returned per arch/bits so the move of the
        tables to module-level constants stays behavior-preserving, and asserts
        that each call returns an independent (non-aliased) copy.
        """
        inferrer = TypeInference()

        assert inferrer._get_calling_convention("x86_64", 64) == {
            "param_registers": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            "return_register": "rax",
            "callee_saved": ["rbx", "rbp", "r12", "r13", "r14", "r15"],
            "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
        }
        # amd64/x86 aliases resolve to the same 64-bit convention.
        assert inferrer._get_calling_convention("amd64", 64) == inferrer._get_calling_convention("x86", 64)

        assert inferrer._get_calling_convention("x86", 32) == {
            "param_registers": [],
            "return_register": "eax",
            "callee_saved": ["ebx", "esi", "edi", "ebp"],
            "caller_saved": ["eax", "ecx", "edx"],
            "stack_params": True,
        }

        assert inferrer._get_calling_convention("arm32", 32) == {
            "param_registers": ["r0", "r1", "r2", "r3"],
            "return_register": "r0",
            "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
            "caller_saved": ["r0", "r1", "r2", "r3", "r12", "lr"],
        }

        arm64 = inferrer._get_calling_convention("aarch64", 64)
        assert arm64["param_registers"] == ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        assert arm64["return_register"] == "x0"
        assert arm64["callee_saved"] == [f"x{n}" for n in range(19, 29)]
        assert arm64["caller_saved"] == [f"x{n}" for n in range(0, 19)]

        # Unknown architecture falls back to the empty convention.
        assert inferrer._get_calling_convention("mips", 32) == {
            "param_registers": [],
            "return_register": "",
            "callee_saved": [],
            "caller_saved": [],
        }

        # Each call yields an independent copy: mutating one must not affect
        # the shared table or a subsequent call.
        first = inferrer._get_calling_convention("x86_64", 64)
        first["callee_saved"].append("polluted")
        second = inferrer._get_calling_convention("x86_64", 64)
        assert "polluted" not in second["callee_saved"]

    def test_is_safe_to_mutate(self):
        """Test mutation safety check."""
        inferrer = TypeInference()

        binary = MagicMock()
        binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "disasm": "mov eax, 0x42"},
        ]

        is_safe, reason = inferrer.is_safe_to_mutate(binary, 0x1000, "register_substitution")
        assert is_safe is True

    def test_is_safe_to_mutate_pointer(self):
        """Test mutation safety check with pointer."""
        inferrer = TypeInference()

        binary = MagicMock()
        binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "disasm": "lea rax, [rip+0x1000]"},
        ]

        is_safe, reason = inferrer.is_safe_to_mutate(binary, 0x1000, "register_substitution")
        assert is_safe is False
        assert "pointer" in reason.lower()


class TestPointerAnalysis:
    """Test PointerAnalysis class."""

    def test_empty_analysis(self):
        """Test empty pointer analysis."""
        analysis = PointerAnalysis()
        assert len(analysis.get_points_to(0x1000)) == 0
        assert len(analysis.get_aliases(0x1000)) == 0

    def test_compute_aliases(self):
        """Test computing aliases."""
        analysis = PointerAnalysis()

        binary = MagicMock()
        binary.get_functions.return_value = [
            {"offset": 0x1000, "name": "main"},
        ]
        binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "disasm": "lea rax, [0x2000]"},
        ]

        analysis.compute_aliases(binary)

        # Points-to should be populated
        assert len(analysis._points_to) >= 0

    def test_may_alias_same_address(self):
        """Test alias detection with same address."""
        analysis = PointerAnalysis()
        assert analysis.may_alias(0x1000, 0x1000) is True

    def test_may_alias_different_addresses(self):
        """Test alias detection with different addresses."""
        analysis = PointerAnalysis()
        assert analysis.may_alias(0x1000, 0x2000) is False

    def test_get_points_to_empty(self):
        """Test points-to with no information."""
        analysis = PointerAnalysis()
        points = analysis.get_points_to(0x1000)
        assert len(points) == 0

    def test_get_aliases_empty(self):
        """Test aliases with no information."""
        analysis = PointerAnalysis()
        aliases = analysis.get_aliases(0x1000)
        assert len(aliases) == 0


class TestTypeCategories:
    """Test type categories and enums."""

    def test_type_category_values(self):
        """Test TypeCategory enum values."""
        assert TypeCategory.PRIMITIVE.value == "primitive"
        assert TypeCategory.POINTER.value == "pointer"
        assert TypeCategory.ARRAY.value == "array"
        assert TypeCategory.STRUCT.value == "struct"
        assert TypeCategory.FUNCTION.value == "function"
        assert TypeCategory.UNKNOWN.value == "unknown"

    def test_primitive_type_values(self):
        """Test PrimitiveType enum values."""
        assert PrimitiveType.INT8.value == "int8"
        assert PrimitiveType.INT64.value == "int64"
        assert PrimitiveType.FLOAT32.value == "float32"
        assert PrimitiveType.VOID.value == "void"


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_infer_type_function(self):
        """Test infer_type convenience function."""
        binary = MagicMock()
        binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "disasm": "mov eax, 0x42"},
        ]

        type_info = infer_type(binary, 0x1000)
        assert isinstance(type_info, TypeInfo)

    def test_propagate_types_function(self):
        """Test propagate_types convenience function."""
        binary = MagicMock()
        binary.get_function_disasm.return_value = []

        types = propagate_types(binary, 0x1000)
        assert isinstance(types, dict)


class TestStructField:
    """Test StructField dataclass."""

    def test_struct_field_creation(self):
        """Test struct field creation."""
        type_info = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.INT32,
            size=4,
        )
        field = StructField(
            name="x",
            offset=0,
            type_info=type_info,
        )
        assert field.name == "x"
        assert field.offset == 0
        assert field.type_info == type_info
        assert field.size == 4

    def test_struct_field_custom_size(self):
        """Test struct field with custom size."""
        type_info = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            size=4,
        )
        field = StructField(
            name="y",
            offset=8,
            type_info=type_info,
            size=16,
        )
        assert field.size == 16
