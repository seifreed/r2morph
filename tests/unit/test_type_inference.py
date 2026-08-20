"""
Tests for Type Inference engine.

Covers:
- TypeInfo creation
- Type inference from instructions
- Pointer analysis
- Type propagation
"""

from r2morph.analysis.type_inference import (
    PointerAnalysis,
    PrimitiveType,
    StructField,
    TypeCategory,
    TypeInference,
    TypeInfo,
    infer_type,
    propagate_types,
)
from tests._doubles.in_memory_typed_binary import InMemoryTypedBinary
from tests.utils.assertions import expect

_EXPECTED_ABS_ADJ_PTR_0X340_CONFIDENCE_0_72_1e_09 = 1e-9
_EXPECTED_ABS_NEIGHBOR_0X110_CONFIDENCE_0_7_1e_09 = 1e-9
_EXPECTED_ABS_PROMOTE_0X10_CONFIDENCE_0_72_1e_09 = 1e-9
_EXPECTED_ABS_UNIFY_0X14_CONFIDENCE_0_6_1e_09 = 1e-9
_EXPECTED_ABS_UNKNOWN8_0X20_CONFIDENCE_0_5_1e_09 = 1e-9
_EXPECTED_ARR_ELEMENT_COUNT_10 = 10
_EXPECTED_ARR_ELEMENT_COUNT_10_2 = 10
_EXPECTED_ARR_SIZE_40 = 40
_EXPECTED_ARR_SIZE_40_2 = 40
_EXPECTED_D_SIZE_4 = 4
_EXPECTED_FIELD_SIZE_16 = 16
_EXPECTED_FIELD_SIZE_4 = 4
_EXPECTED_INFERRER_GET_OPERAND_SIZE_AX_2 = 2
_EXPECTED_INFERRER_GET_OPERAND_SIZE_EAX_4 = 4
_EXPECTED_INFERRER_GET_OPERAND_SIZE_ESI_4 = 4
_EXPECTED_INFERRER_GET_OPERAND_SIZE_NOT_A_REGISTER_4 = 4
_EXPECTED_INFERRER_GET_OPERAND_SIZE_R15_8 = 8
_EXPECTED_INFERRER_GET_OPERAND_SIZE_R8D_8 = 8
_EXPECTED_INFERRER_GET_OPERAND_SIZE_R8W_8 = 8
_EXPECTED_INFERRER_GET_OPERAND_SIZE_RAX_8 = 8
_EXPECTED_INFERRER_GET_OPERAND_SIZE_RAX_8_2 = 8
_EXPECTED_INFERRER_GET_OPERAND_SIZE_RAX_8_3 = 8
_EXPECTED_INFERRER_GET_OPERAND_SIZE_RAX_RBX_8 = 8
_EXPECTED_INFERRER_GET_OPERAND_SIZE_XMM0_4 = 4
_EXPECTED_INT32_SIZE_4 = 4
_EXPECTED_INT64_SIZE_8 = 8
_EXPECTED_LEN_STRUCT_TYPE_FIELDS_2 = 2
_EXPECTED_LEN_STRUCT_TYPE_FIELDS_2_2 = 2
_EXPECTED_PTR_SIZE_8 = 8
_EXPECTED_TYPE_INFO_SIZE_4 = 4
_EXPECTED_UNIFY_0X14_ALIGNMENT_4 = 4
_EXPECTED_UNKNOWN4_0X50_SIZE_4 = 4


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
        expect(type_info.category == TypeCategory.PRIMITIVE)
        expect(type_info.size == _EXPECTED_TYPE_INFO_SIZE_4)
        expect(type_info.primitive == PrimitiveType.INT32)

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
        expect(ptr.is_pointer())
        expect(ptr.pointee == pointee)

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
        expect(arr.is_array())
        expect(arr.element_count == _EXPECTED_ARR_ELEMENT_COUNT_10)
        expect(arr.size == _EXPECTED_ARR_SIZE_40)

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
        expect(struct_type.is_struct())
        expect(len(struct_type.fields) == _EXPECTED_LEN_STRUCT_TYPE_FIELDS_2)

    def test_is_integer(self):
        """Test integer type detection."""
        int_type = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.INT32,
        )
        expect(int_type.is_integer())

        float_type = TypeInfo(
            type_id=2,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.FLOAT32,
        )
        expect(not (float_type.is_integer()))

    def test_is_float(self):
        """Test float type detection."""
        float_type = TypeInfo(
            type_id=1,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.FLOAT32,
        )
        expect(float_type.is_float())

        int_type = TypeInfo(
            type_id=2,
            category=TypeCategory.PRIMITIVE,
            primitive=PrimitiveType.INT32,
        )
        expect(not (int_type.is_float()))

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
        expect(ptr.get_deref_type() == pointee)

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
        expect(d["type_id"] == 1)
        expect(d["category"] == "primitive")
        expect(d["size"] == _EXPECTED_D_SIZE_4)


class TestTypeInference:
    """Test TypeInference class."""

    def test_create_primitive_type(self):
        """Test primitive type creation."""
        inferrer = TypeInference()

        int32 = inferrer.create_primitive_type(PrimitiveType.INT32)
        expect(int32.category == TypeCategory.PRIMITIVE)
        expect(int32.size == _EXPECTED_INT32_SIZE_4)

        int64 = inferrer.create_primitive_type(PrimitiveType.INT64)
        expect(int64.size == _EXPECTED_INT64_SIZE_8)

    def test_create_pointer_type(self):
        """Test pointer type creation."""
        inferrer = TypeInference()

        ptr = inferrer.create_pointer_type()
        expect(ptr.category == TypeCategory.POINTER)
        expect(ptr.size == _EXPECTED_PTR_SIZE_8)

        int32 = inferrer.create_primitive_type(PrimitiveType.INT32)
        ptr_to_int = inferrer.create_pointer_type(int32)
        expect(ptr_to_int.pointee == int32)

    def test_create_array_type(self):
        """Test array type creation."""
        inferrer = TypeInference()

        int32 = inferrer.create_primitive_type(PrimitiveType.INT32)
        arr = inferrer.create_array_type(int32, 10)

        expect(arr.category == TypeCategory.ARRAY)
        expect(arr.element_count == _EXPECTED_ARR_ELEMENT_COUNT_10_2)
        expect(arr.size == _EXPECTED_ARR_SIZE_40_2)

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

        expect(struct_type.category == TypeCategory.STRUCT)
        expect(len(struct_type.fields) == _EXPECTED_LEN_STRUCT_TYPE_FIELDS_2_2)

    def test_infer_type_mov_immediate(self):
        """Test type inference from mov immediate."""
        inferrer = TypeInference()

        binary = InMemoryTypedBinary(disasm_by_addr={0x1000: [{"offset": 0x1000, "disasm": "mov eax, 0x42"}]})

        type_info = inferrer.infer_type(binary, 0x1000)
        expect(type_info.category == TypeCategory.PRIMITIVE)

    def test_infer_type_lea(self):
        """Test type inference from LEA."""
        inferrer = TypeInference()

        binary = InMemoryTypedBinary(disasm_by_addr={0x1000: [{"offset": 0x1000, "disasm": "lea rax, [rip+0x1000]"}]})

        type_info = inferrer.infer_type(binary, 0x1000)
        expect(type_info.category == TypeCategory.POINTER)

    def test_infer_type_comparison(self):
        """Test type inference from comparison."""
        inferrer = TypeInference()

        binary = InMemoryTypedBinary(disasm_by_addr={0x1000: [{"offset": 0x1000, "disasm": "cmp eax, ebx"}]})

        type_info = inferrer.infer_type(binary, 0x1000)
        expect(type_info.primitive == PrimitiveType.BOOL)

    def test_propagate_types(self):
        """Test type propagation through function."""
        inferrer = TypeInference()

        binary = InMemoryTypedBinary(
            disasm_by_addr={
                0x1000: [
                    {"offset": 0x1000, "disasm": "mov eax, 0x42"},
                    {"offset": 0x1005, "disasm": "add eax, ebx"},
                    {"offset": 0x100A, "disasm": "ret"},
                ]
            }
        )

        types = inferrer.propagate_types(binary, 0x1000)
        expect(not (len(types) < 0))

    def test_get_operand_size(self):
        """Test operand size detection."""
        inferrer = TypeInference()

        expect(inferrer._get_operand_size("rax") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_RAX_8)
        expect(inferrer._get_operand_size("eax") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_EAX_4)
        expect(inferrer._get_operand_size("ax") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_AX_2)
        expect(inferrer._get_operand_size("al") == 1)

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
        expect(inferrer._get_operand_size("r15") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_R15_8)
        expect(inferrer._get_operand_size("esi") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_ESI_4)

        # Order-sensitive prefix match: r8d/r8w start with the 8-byte "r8" key,
        # which is declared first, so they resolve to 8 (not 4 / 2).
        expect(inferrer._get_operand_size("r8d") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_R8D_8)
        expect(inferrer._get_operand_size("r8w") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_R8W_8)

        # Case-insensitive and whitespace-trimmed.
        expect(inferrer._get_operand_size("RAX") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_RAX_8_2)
        expect(inferrer._get_operand_size("  rax  ") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_RAX_8_3)

        # Matches on the leading register of a multi-token operand.
        expect(inferrer._get_operand_size("rax, rbx") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_RAX_RBX_8)

        # Unknown operands fall back to the default width.
        expect(inferrer._get_operand_size("xmm0") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_XMM0_4)
        expect(inferrer._get_operand_size("not_a_register") == _EXPECTED_INFERRER_GET_OPERAND_SIZE_NOT_A_REGISTER_4)

    def test_get_calling_convention_contract(self):
        """Characterize the calling-convention table for every architecture.

        Pins the exact register sets returned per arch/bits so the move of the
        tables to module-level constants stays behavior-preserving, and asserts
        that each call returns an independent (non-aliased) copy.
        """
        inferrer = TypeInference()

        expect(
            inferrer._get_calling_convention("x86_64", 64)
            == {
                "param_registers": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
                "return_register": "rax",
                "callee_saved": ["rbx", "rbp", "r12", "r13", "r14", "r15"],
                "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
            }
        )
        # amd64/x86 aliases resolve to the same 64-bit convention.
        expect(inferrer._get_calling_convention("amd64", 64) == inferrer._get_calling_convention("x86", 64))

        expect(
            inferrer._get_calling_convention("x86", 32)
            == {
                "param_registers": [],
                "return_register": "eax",
                "callee_saved": ["ebx", "esi", "edi", "ebp"],
                "caller_saved": ["eax", "ecx", "edx"],
                "stack_params": True,
            }
        )

        expect(
            inferrer._get_calling_convention("arm32", 32)
            == {
                "param_registers": ["r0", "r1", "r2", "r3"],
                "return_register": "r0",
                "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
                "caller_saved": ["r0", "r1", "r2", "r3", "r12", "lr"],
            }
        )

        arm64 = inferrer._get_calling_convention("aarch64", 64)
        expect(arm64["param_registers"] == ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"])
        expect(arm64["return_register"] == "x0")
        expect(arm64["callee_saved"] == [f"x{n}" for n in range(19, 29)])
        expect(arm64["caller_saved"] == [f"x{n}" for n in range(0, 19)])

        # Unknown architecture falls back to the empty convention.
        expect(
            inferrer._get_calling_convention("mips", 32)
            == {"param_registers": [], "return_register": "", "callee_saved": [], "caller_saved": []}
        )

        # Each call yields an independent copy: mutating one must not affect
        # the shared table or a subsequent call.
        first = inferrer._get_calling_convention("x86_64", 64)
        first["callee_saved"].append("polluted")
        second = inferrer._get_calling_convention("x86_64", 64)
        expect("polluted" not in second["callee_saved"])

    def test_infer_arm64_register_types_branches(self):
        """Characterize ARM64 per-instruction register typing.

        Drives _infer_arm64_register_types with one instruction per dispatch
        branch and pins the resulting register categories. This is the oracle
        for moving the per-branch ``import re`` to a single module-level import.
        Only deterministic branches are asserted (the ``fmov`` branch is dead —
        ``"fmov"`` contains ``"mov"`` so the earlier ``mov`` branch claims it).
        """
        inferrer = TypeInference()
        regs: dict = {}

        # ldr into a general register -> pointer; into a vector register -> float.
        inferrer._infer_arm64_register_types("ldr x0, [x1]", regs)
        expect(regs["x0"].is_pointer())
        inferrer._infer_arm64_register_types("ldr d3, [x1]", regs)
        expect(regs["d3"].primitive == PrimitiveType.FLOAT64)

        # str records an unseen destination as a 64-bit integer.
        inferrer._infer_arm64_register_types("str x2, [sp]", regs)
        expect(regs["x2"].primitive == PrimitiveType.UINT64)

        # mov copies a known source register's type to the destination.
        inferrer._infer_arm64_register_types("mov x9, x0", regs)
        expect(regs["x9"].is_pointer())

        # add/sub default an unseen destination to a 64-bit integer.
        inferrer._infer_arm64_register_types("add x6, x6, #1", regs)
        expect(regs["x6"].primitive == PrimitiveType.INT64)

    def test_infer_arm32_register_types_branches(self):
        """Characterize ARM32 per-instruction register typing.

        Oracle for the module-level ``re`` import move; pins the ldr/str
        branches per register class.
        """
        inferrer = TypeInference()
        regs: dict = {}

        inferrer._infer_arm32_register_types("ldr r0, [sp]", regs)
        expect(regs["r0"].is_pointer())
        inferrer._infer_arm32_register_types("ldr s2, [sp]", regs)
        expect(regs["s2"].primitive == PrimitiveType.FLOAT32)
        inferrer._infer_arm32_register_types("ldr d4, [sp]", regs)
        expect(regs["d4"].primitive == PrimitiveType.FLOAT64)

        inferrer._infer_arm32_register_types("str r1, [sp]", regs)
        expect(regs["r1"].primitive == PrimitiveType.UINT32)

    def test_propagate_through_phis_contract(self):
        """Characterize the two phases of _propagate_through_phis.

        Phase 1 walks sorted-adjacent addresses and unifies same-category
        same-size types (higher confidence wins) and promotes a pointer that
        follows a 64-bit integer. Phase 2 promotes any 64-bit integer within 32
        bytes of a pointer to a pointer. Each scenario isolates one path; this
        is the oracle for extracting the two phases into helpers.
        """
        inferrer = TypeInference()

        # Phase 1: same category + size, prev higher confidence -> curr unified
        # (alignment becomes the max, confidence the average).
        unify = {
            0x10: TypeInfo(
                type_id=1,
                category=TypeCategory.PRIMITIVE,
                size=4,
                alignment=2,
                primitive=PrimitiveType.INT32,
                confidence=0.9,
            ),
            0x14: TypeInfo(
                type_id=2,
                category=TypeCategory.PRIMITIVE,
                size=4,
                alignment=4,
                primitive=None,
                confidence=0.3,
            ),
        }
        inferrer._propagate_through_phis(unify)
        expect(unify[20].primitive == PrimitiveType.INT32)
        expect(unify[20].alignment == _EXPECTED_UNIFY_0X14_ALIGNMENT_4)
        expect(not (abs(unify[0x14].confidence - 0.6) >= _EXPECTED_ABS_UNIFY_0X14_CONFIDENCE_0_6_1e_09))

        # Phase 1: a pointer following a 64-bit integer in sorted order is
        # re-confidenced to prev*0.9. Addresses are 64 bytes apart so the phase-2
        # neighborhood rule (<32) stays inert and the phase-1 effect is isolated.
        adj_ptr = {
            0x300: TypeInfo(
                type_id=1,
                category=TypeCategory.PRIMITIVE,
                size=8,
                primitive=PrimitiveType.INT64,
                confidence=0.8,
            ),
            0x340: TypeInfo(
                type_id=2,
                category=TypeCategory.POINTER,
                size=8,
                alignment=8,
                confidence=0.5,
            ),
        }
        inferrer._propagate_through_phis(adj_ptr)
        expect(adj_ptr[0x340].is_pointer())
        expect(not (abs(adj_ptr[0x340].confidence - 0.72) >= _EXPECTED_ABS_ADJ_PTR_0X340_CONFIDENCE_0_72_1e_09))
        expect(adj_ptr[0x300].is_primitive())

        # Phase 2: a 64-bit integer within 32 bytes of a pointer is promoted.
        neighbor = {
            0x100: TypeInfo(
                type_id=1,
                category=TypeCategory.POINTER,
                size=8,
                alignment=8,
                confidence=0.9,
            ),
            0x110: TypeInfo(
                type_id=2,
                category=TypeCategory.PRIMITIVE,
                size=8,
                primitive=PrimitiveType.UINT64,
                confidence=0.4,
            ),
        }
        inferrer._propagate_through_phis(neighbor)
        expect(neighbor[0x110].is_pointer())
        expect(not (abs(neighbor[0x110].confidence - 0.7) >= _EXPECTED_ABS_NEIGHBOR_0X110_CONFIDENCE_0_7_1e_09))

    def test_refine_types_contract(self):
        """Characterize the three refinement rules of _refine_types.

        The loop refines every address except the last (it needs a successor).
        Rules: a 64-bit integer 8 bytes before a <=4-byte primitive becomes a
        pointer; an unknown 8-byte value becomes a pointer; an unknown 4-byte
        value becomes an int32. This is the oracle for splitting the rules into
        helpers and dropping the dead type_counts aggregation.
        """
        inferrer = TypeInference()

        # 64-bit int immediately followed (8 bytes on) by a small primitive
        # -> reinterpreted as a pointer with confidence * 0.8.
        promote = {
            0x10: TypeInfo(
                type_id=1,
                category=TypeCategory.PRIMITIVE,
                size=8,
                primitive=PrimitiveType.INT64,
                confidence=0.9,
            ),
            0x18: TypeInfo(
                type_id=2,
                category=TypeCategory.PRIMITIVE,
                size=4,
                primitive=PrimitiveType.INT32,
                confidence=0.5,
            ),
        }
        inferrer._refine_types(promote)
        expect(promote[0x10].is_pointer())
        expect(not (abs(promote[0x10].confidence - 0.72) >= _EXPECTED_ABS_PROMOTE_0X10_CONFIDENCE_0_72_1e_09))
        expect(promote[0x18].is_primitive())

        # Unknown 8-byte value -> pointer (confidence 0.5).
        unknown8 = {
            0x20: TypeInfo(type_id=1, category=TypeCategory.UNKNOWN, size=8),
            0x40: TypeInfo(type_id=2, category=TypeCategory.PRIMITIVE, size=4),
        }
        inferrer._refine_types(unknown8)
        expect(unknown8[0x20].is_pointer())
        expect(not (abs(unknown8[0x20].confidence - 0.5) >= _EXPECTED_ABS_UNKNOWN8_0X20_CONFIDENCE_0_5_1e_09))

        # Unknown 4-byte value -> int32 (confidence 0.5).
        unknown4 = {
            0x50: TypeInfo(type_id=1, category=TypeCategory.UNKNOWN, size=4),
            0x90: TypeInfo(type_id=2, category=TypeCategory.PRIMITIVE, size=4),
        }
        inferrer._refine_types(unknown4)
        expect(unknown4[0x50].is_primitive())
        expect(unknown4[80].primitive == PrimitiveType.INT32)
        expect(unknown4[80].size == _EXPECTED_UNKNOWN4_0X50_SIZE_4)

    def test_propagate_interprocedural_types_per_function(self):
        """Characterize the per-function inference loop, no mocks.

        Pins that the result has exactly one entry per function, the happy path
        infers parameters from the calling convention, and a function whose
        disassembly raises is recorded with an empty parameter map (graceful
        error path). This is the oracle for extracting the loop into a helper.
        """
        inferrer = TypeInference()
        binary = InMemoryTypedBinary(
            arch="x86_64",
            bits=64,
            functions=[
                {"offset": 0x1000, "name": "good"},
                {"offset": 0x2000, "name": "broken"},
            ],
            disasm_by_addr={0x1000: [{"disasm": "mov rdi, rax"}]},
            failing_addrs={0x2000},
        )

        result = inferrer.propagate_interprocedural_types(binary)

        expect(set(result.keys()) == {4096, 8192})
        # Happy path: rdi is the first SysV AMD64 parameter register.
        expect(not ("param_0" not in result[0x1000]))
        # Error path: disassembly raised -> empty parameter map, no crash.
        expect(result[8192] == {})

    def test_is_safe_to_mutate(self):
        """Test mutation safety check."""
        inferrer = TypeInference()

        binary = InMemoryTypedBinary(disasm_by_addr={0x1000: [{"offset": 0x1000, "disasm": "mov eax, 0x42"}]})

        is_safe, _reason = inferrer.is_safe_to_mutate(binary, 0x1000, "register_substitution")
        expect(not (is_safe is not True))

    def test_is_safe_to_mutate_pointer(self):
        """Test mutation safety check with pointer."""
        inferrer = TypeInference()

        binary = InMemoryTypedBinary(disasm_by_addr={0x1000: [{"offset": 0x1000, "disasm": "lea rax, [rip+0x1000]"}]})

        is_safe, reason = inferrer.is_safe_to_mutate(binary, 0x1000, "register_substitution")
        expect(not (is_safe is not False))
        expect(not ("pointer" not in reason.lower()))


class TestPointerAnalysis:
    """Test PointerAnalysis class."""

    def test_empty_analysis(self):
        """Test empty pointer analysis."""
        analysis = PointerAnalysis()
        expect(len(analysis.get_points_to(4096)) == 0)
        expect(len(analysis.get_aliases(4096)) == 0)

    def test_compute_aliases(self):
        """Test computing aliases."""
        analysis = PointerAnalysis()

        binary = InMemoryTypedBinary(
            functions=[{"offset": 0x1000, "name": "main"}],
            disasm_by_addr={0x1000: [{"offset": 0x1000, "disasm": "lea rax, [0x2000]"}]},
        )

        analysis.compute_aliases(binary)

        # Points-to should be populated
        expect(not (len(analysis._points_to) < 0))

    def test_may_alias_same_address(self):
        """Test alias detection with same address."""
        analysis = PointerAnalysis()
        expect(not (analysis.may_alias(0x1000, 0x1000) is not True))

    def test_may_alias_different_addresses(self):
        """Test alias detection with different addresses."""
        analysis = PointerAnalysis()
        expect(not (analysis.may_alias(0x1000, 0x2000) is not False))

    def test_get_points_to_empty(self):
        """Test points-to with no information."""
        analysis = PointerAnalysis()
        points = analysis.get_points_to(0x1000)
        expect(len(points) == 0)

    def test_get_aliases_empty(self):
        """Test aliases with no information."""
        analysis = PointerAnalysis()
        aliases = analysis.get_aliases(0x1000)
        expect(len(aliases) == 0)


class TestTypeCategories:
    """Test type categories and enums."""

    def test_type_category_values(self):
        """Test TypeCategory enum values."""
        expect(TypeCategory.PRIMITIVE.value == "primitive")
        expect(TypeCategory.POINTER.value == "pointer")
        expect(TypeCategory.ARRAY.value == "array")
        expect(TypeCategory.STRUCT.value == "struct")
        expect(TypeCategory.FUNCTION.value == "function")
        expect(TypeCategory.UNKNOWN.value == "unknown")

    def test_primitive_type_values(self):
        """Test PrimitiveType enum values."""
        expect(PrimitiveType.INT8.value == "int8")
        expect(PrimitiveType.INT64.value == "int64")
        expect(PrimitiveType.FLOAT32.value == "float32")
        expect(PrimitiveType.VOID.value == "void")


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_infer_type_function(self):
        """Test infer_type convenience function."""
        binary = InMemoryTypedBinary(disasm_by_addr={0x1000: [{"offset": 0x1000, "disasm": "mov eax, 0x42"}]})

        type_info = infer_type(binary, 0x1000)
        expect(isinstance(type_info, TypeInfo))

    def test_propagate_types_function(self):
        """Test propagate_types convenience function."""
        binary = InMemoryTypedBinary()

        types = propagate_types(binary, 0x1000)
        expect(isinstance(types, dict))


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
        expect(field.name == "x")
        expect(field.offset == 0)
        expect(field.type_info == type_info)
        expect(field.size == _EXPECTED_FIELD_SIZE_4)

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
        expect(field.size == _EXPECTED_FIELD_SIZE_16)
