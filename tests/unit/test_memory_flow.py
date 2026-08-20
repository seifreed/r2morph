"""
Unit tests for memory flow analysis.
"""

import importlib

import pytest

from r2morph.analysis.memory_flow import (
    InterproceduralDataFlowAnalyzer,
    MemoryAccess,
    MemoryAccessType,
    MemoryDependency,
    MemoryFlowAnalyzer,
    MemoryLocation,
)
from tests.utils.assertions import expect

_EXPECTED_ACCESS_ADDRESS_1280 = 0x500
_EXPECTED_ACCESS_LOCATION_SIZE_4 = 4
_EXPECTED_ANALYZER_ACCESSES_1792 = 0x700
_EXPECTED_ANALYZER_ACCESSES_2048 = 0x800
_EXPECTED_D_SIZE_8 = 8
_EXPECTED_LEN_RESULT_FUNCTION_SUMMARIES_2 = 2
_EXPECTED_LOC_ADDRESS_4096 = 0x1000
_EXPECTED_LOC_SIZE_8 = 8
_EXPECTED_SIZE_16 = 16
_EXPECTED_SIZE_2 = 2
_EXPECTED_SIZE_2_2 = 2
_EXPECTED_SIZE_4 = 4
_EXPECTED_SIZE_4_2 = 4
_EXPECTED_SIZE_8 = 8


class TestMemoryLocation:
    def test_memory_location_creation(self):
        loc = MemoryLocation(address=0x1000, size=8)
        expect(loc.address == _EXPECTED_LOC_ADDRESS_4096)
        expect(loc.size == _EXPECTED_LOC_SIZE_8)
        expect(loc.name == "")
        expect(loc.location_type == "unknown")

    def test_memory_location_with_name(self):
        loc = MemoryLocation(address=0x1000, size=4, name="buffer")
        expect(loc.name == "buffer")

    def test_memory_location_repr(self):
        loc = MemoryLocation(address=0x1000, size=4, name="var_x")
        expect(not ("0x1000" not in repr(loc)))
        expect(not ("var_x" not in repr(loc)))

    def test_memory_location_hash(self):
        loc1 = MemoryLocation(address=0x1000, size=8)
        loc2 = MemoryLocation(address=0x1000, size=8)
        loc3 = MemoryLocation(address=0x1000, size=4)

        expect(hash(loc1) == hash(loc2))
        expect(hash(loc1) != hash(loc3))

    def test_memory_location_overlaps(self):
        loc1 = MemoryLocation(address=0x1000, size=8)
        loc2 = MemoryLocation(address=0x1004, size=8)
        loc3 = MemoryLocation(address=0x1010, size=4)

        expect(loc1.overlaps(loc2))
        expect(loc2.overlaps(loc1))
        expect(not (loc1.overlaps(loc3)))

    def test_memory_location_to_dict(self):
        loc = MemoryLocation(address=0x1000, size=8, name="test", location_type="stack")
        d = loc.to_dict()
        expect(d["address"] == "0x1000")
        expect(d["size"] == _EXPECTED_D_SIZE_8)
        expect(d["name"] == "test")
        expect(d["type"] == "stack")


class TestMemoryAccess:
    def test_memory_access_creation(self):
        loc = MemoryLocation(address=0x1000, size=4)
        access = MemoryAccess(
            address=0x500,
            location=loc,
            access_type=MemoryAccessType.READ,
        )
        expect(access.address == _EXPECTED_ACCESS_ADDRESS_1280)
        expect(access.access_type == MemoryAccessType.READ)

    def test_memory_access_write(self):
        loc = MemoryLocation(address=0x2000, size=8)
        access = MemoryAccess(
            address=0x100,
            location=loc,
            access_type=MemoryAccessType.WRITE,
            instruction="mov [rax], rbx",
        )
        expect(access.access_type == MemoryAccessType.WRITE)
        expect(not ("mov" not in access.instruction))

    def test_memory_access_to_dict(self):
        loc = MemoryLocation(address=0x1000, size=4)
        access = MemoryAccess(
            address=0x500,
            location=loc,
            access_type=MemoryAccessType.READ,
            instruction="mov eax, [rbx]",
            registers_involved=["eax", "rbx"],
        )
        d = access.to_dict()
        expect(not ("0x500" not in d["instruction_address"]))
        expect(d["access_type"] == "read")
        expect(not ("eax" not in d["registers"]))


class TestMemoryDependency:
    def test_memory_dependency_creation(self):
        loc1 = MemoryLocation(address=0x1000, size=4)
        loc2 = MemoryLocation(address=0x1000, size=4)

        access1 = MemoryAccess(address=0x100, location=loc1, access_type=MemoryAccessType.WRITE)
        access2 = MemoryAccess(address=0x200, location=loc2, access_type=MemoryAccessType.READ)

        dep = MemoryDependency(
            source=access1,
            target=access2,
            dependency_type="flow",
        )
        expect(dep.dependency_type == "flow")
        expect(not (dep.is_alias))

    def test_memory_dependency_alias(self):
        loc1 = MemoryLocation(address=0x1000, size=4)
        loc2 = MemoryLocation(address=0x1002, size=4)

        access1 = MemoryAccess(address=0x100, location=loc1, access_type=MemoryAccessType.WRITE)
        access2 = MemoryAccess(address=0x200, location=loc2, access_type=MemoryAccessType.READ)

        dep = MemoryDependency(
            source=access1,
            target=access2,
            dependency_type="flow",
            is_alias=True,
        )
        expect(dep.is_alias)

    def test_memory_dependency_to_dict(self):
        loc = MemoryLocation(address=0x1000, size=4)
        access1 = MemoryAccess(address=0x100, location=loc, access_type=MemoryAccessType.WRITE)
        access2 = MemoryAccess(address=0x200, location=loc, access_type=MemoryAccessType.READ)

        dep = MemoryDependency(source=access1, target=access2, dependency_type="anti")
        d = dep.to_dict()
        expect(d["type"] == "anti")


class TestMemoryFlowAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return MemoryFlowAnalyzer()

    def test_analyzer_initialization(self, analyzer):
        expect(len(analyzer._accesses) == 0)
        expect(len(analyzer._locations) == 0)

    def test_analyze_function_empty(self, analyzer):
        instructions = []
        result = analyzer.analyze_function(instructions, 0x1000)

        expect(not ("memory_accesses" not in result))
        expect(not ("locations" not in result))
        expect(not ("dependencies" not in result))

    def test_analyze_function_simple_mov(self, analyzer):
        instructions = [
            {"offset": 0x1000, "disasm": "mov eax, [0x2000]"},
            {"offset": 0x1005, "disasm": "mov [0x3000], eax"},
        ]

        result = analyzer.analyze_function(instructions, 0x1000)

        expect(not ("memory_accesses" not in result))
        expect(not ("stack_frame" not in result))

    def test_analyze_function_push_pop(self, analyzer):
        instructions = [
            {"offset": 0x1000, "disasm": "push rax"},
            {"offset": 0x1002, "disasm": "pop rbx"},
        ]

        result = analyzer.analyze_function(instructions, 0x1000)

        expect(not ("memory_accesses" not in result))
        expect(not ("stack_frame" not in result))
        expect(not (len(result["stack_frame"]["saved_regs"]) <= 0))

    def test_analyze_stack_frame(self, analyzer):
        instructions = [
            {"offset": 0x1000, "disasm": "push rbp"},
            {"offset": 0x1002, "disasm": "mov rbp, rsp"},
            {"offset": 0x1005, "disasm": "sub rsp, 0x20"},
            {"offset": 0x1009, "disasm": "mov [rbp-8], eax"},
        ]

        frame = analyzer._analyze_stack_frame(instructions, 0x1000)

        expect(not ("local_vars" not in frame))
        expect(not ("frame_size" not in frame))
        expect(not (frame["frame_size"] <= 0))

    def test_analyze_stack_frame_exact_output(self, analyzer):
        """Characterize the exact stack-frame dict (§5 oracle for refactors).

        Pins current behavior: a ``mov reg, [rbp-N]`` load reaches the
        ``[rbp`` branch but that branch's regex only matches the *store*
        form ``mov [mem], reg``, so the load records no local var.
        """
        instructions = [
            {"offset": 0x1000, "disasm": "push rbp"},
            {"offset": 0x1004, "disasm": "mov [rbp-8], eax"},
            {"offset": 0x1008, "disasm": "mov eax, [rbp-16]"},
        ]

        frame = analyzer._analyze_stack_frame(instructions, 0x1000)

        expect(
            frame
            == {
                "saved_regs": [{"register": "rbp", "offset": 0, "address": "0x1000"}],
                "local_vars": [{"name": "var_8", "offset": -8, "size": 4, "access_type": "write", "address": "0x1004"}],
                "arguments": [],
                "frame_size": 8,
                "allocations": [],
            }
        )

    def test_analyze_stack_frame_all_branches_exact(self, analyzer):
        """§5 oracle covering all three decode branches of _analyze_stack_frame:
        push (saved reg + frame growth), ARM ``sub sp, #N`` allocation, and a
        ``mov [sp-N], reg`` local-var store."""
        instructions = [
            {"offset": 0x1000, "disasm": "push rbp"},
            {"offset": 0x1004, "disasm": "sub sp, #32"},
            {"offset": 0x1008, "disasm": "mov [sp-4], w0"},
        ]

        frame = analyzer._analyze_stack_frame(instructions, 0x1000)

        expect(
            frame
            == {
                "saved_regs": [{"register": "rbp", "offset": 0, "address": "0x1000"}],
                "allocations": [{"size": 32, "address": "0x1004"}],
                "local_vars": [{"name": "var_4", "offset": -4, "size": 4, "access_type": "write", "address": "0x1008"}],
                "arguments": [],
                "frame_size": 40,
            }
        )

    def test_analyze_instruction_records_exact_accesses(self, analyzer):
        """Characterize _analyze_instruction's effect on _accesses/_locations.

        §5 oracle pinning the exact MemoryAccess/MemoryLocation produced for
        each decode branch (x86 mov read/write, ARM ldr/str, push/pop) plus
        the two no-op paths (empty disasm, instruction with no memory access).
        """
        stack_frame = {"local_vars": [], "arguments": []}
        cases = [
            (0x100, "mov eax, [0x2000]"),
            (0x200, "mov [0x3000], ebx"),
            (0x300, "ldr x0, [sp, #8]"),
            (0x400, "str w1, [sp, #16]"),
            (0x500, "push rbp"),
            (0x600, "pop rbp"),
            (0x700, ""),
            (0x800, "add eax, ebx"),
        ]
        for addr, disasm in cases:
            analyzer._analyze_instruction(addr, disasm, stack_frame)

        expect(_EXPECTED_ANALYZER_ACCESSES_1792 not in analyzer._accesses)
        expect(_EXPECTED_ANALYZER_ACCESSES_2048 not in analyzer._accesses)

        def summarize(addr):
            (access,) = analyzer._accesses[addr]
            loc = access.location
            return (
                access.access_type,
                access.instruction,
                access.registers_involved,
                loc.address,
                loc.size,
                loc.name,
                loc.location_type,
            )

        expect(
            summarize(256) == (MemoryAccessType.READ, "mov eax, [0x2000]", ["eax"], 8192, 4, "unknown_8192", "unknown")
        )
        expect(
            summarize(512)
            == (MemoryAccessType.WRITE, "mov [0x3000], ebx", ["ebx"], 12288, 4, "unknown_12288", "unknown")
        )
        expect(summarize(768) == (MemoryAccessType.READ, "ldr x0, [sp, #8]", ["x0"], 8, 8, "stack_8", "stack"))
        expect(summarize(1024) == (MemoryAccessType.WRITE, "str w1, [sp, #16]", ["w1"], 16, 4, "stack_16", "stack"))
        expect(summarize(1280) == (MemoryAccessType.WRITE, "push rbp", ["rbp"], -8, 8, "stack", "stack"))
        expect(summarize(1536) == (MemoryAccessType.READ, "pop rbp", ["rbp"], 0, 8, "stack", "stack"))

    def test_analyze_instruction_unmatched_ldr_records_degenerate_access(self, analyzer):
        """Pin the subtle ARM ldr/str default: access_type is set before the
        bracket regex, so an ldr without a ``[mem]`` operand still records a
        degenerate read at address 0 (default size 4, empty name/registers)."""
        analyzer._analyze_instruction(0xA00, "ldr x0, x1", {"local_vars": []})

        (access,) = analyzer._accesses[0xA00]
        expect(access.access_type == MemoryAccessType.READ)
        expect(access.registers_involved == [])
        expect(access.location.address == 0)
        expect(access.location.size == _EXPECTED_ACCESS_LOCATION_SIZE_4)
        expect(access.location.name == "")
        expect(access.location.location_type == "unknown")

    def test_extract_access_size_byte(self, analyzer):
        size = analyzer._extract_access_size("movzx eax, byte ptr [ebx]")
        expect(size == 1)

    def test_extract_access_size_word(self, analyzer):
        size = analyzer._extract_access_size("movzx eax, word ptr [ebx]")
        expect(size == _EXPECTED_SIZE_2)

    def test_extract_access_size_dword(self, analyzer):
        size = analyzer._extract_access_size("mov eax, [ebx]")
        expect(size == _EXPECTED_SIZE_4)

    def test_extract_access_size_qword(self, analyzer):
        size = analyzer._extract_access_size("mov rax, [rbx]")
        expect(size == _EXPECTED_SIZE_8)

    def test_extract_access_size_xmm(self, analyzer):
        size = analyzer._extract_access_size("movdqu xmm0, [rbx]")
        expect(size == _EXPECTED_SIZE_16)

    def test_extract_arm_access_size_byte(self, analyzer):
        size = analyzer._extract_arm_access_size("ldrb w0, [x1]")
        expect(size == 1)

    def test_extract_arm_access_size_word(self, analyzer):
        size = analyzer._extract_arm_access_size("ldrh w0, [x1]")
        expect(size == _EXPECTED_SIZE_2_2)

    def test_extract_arm_access_size_dword(self, analyzer):
        size = analyzer._extract_arm_access_size("ldr w0, [x1]")
        expect(size == _EXPECTED_SIZE_4_2)

    def test_compute_dependencies_empty(self, analyzer):
        deps = analyzer._compute_dependencies()
        expect(deps == [])

    def test_detect_aliases_empty(self, analyzer):
        aliases = analyzer._detect_aliases()
        expect(aliases == {})

    def test_analyze_function_arm_str(self, analyzer):
        instructions = [
            {"offset": 0x1000, "disasm": "str x0, [sp, #8]"},
        ]

        result = analyzer.analyze_function(instructions, 0x1000)

        expect(not ("memory_accesses" not in result))


class TestInterproceduralDataFlowAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return InterproceduralDataFlowAnalyzer()

    def test_analyzer_initialization(self, analyzer):
        expect(len(analyzer._function_summaries) == 0)
        expect(len(analyzer._call_graph) == 0)

    def test_analyze_program_basic(self, analyzer):
        functions = [
            {"offset": 0x1000, "instructions": [{"offset": 0x1000, "disasm": "mov eax, 1"}]},
        ]
        call_graph = {0x1000: []}

        result = analyzer.analyze_program(functions, call_graph)

        expect(not ("function_summaries" not in result))
        expect(not ("call_graph" not in result))

    def test_analyze_program_with_calls(self, analyzer):
        functions = [
            {"offset": 0x1000, "instructions": [{"offset": 0x1000, "disasm": "call 0x2000"}]},
            {"offset": 0x2000, "instructions": [{"offset": 0x2000, "disasm": "ret"}]},
        ]
        call_graph = {0x1000: [0x2000], 0x2000: []}

        result = analyzer.analyze_program(functions, call_graph)

        expect(len(result["function_summaries"]) == _EXPECTED_LEN_RESULT_FUNCTION_SUMMARIES_2)

    def test_analyze_function_summary_exact_output(self, analyzer):
        """§5 oracle: pin _analyze_function_summary's effect classification.

        modified_registers is a set materialized to a list, so its order is
        not deterministic across runs; assert it order-independently.
        """
        instructions = [
            {"offset": 0x1000, "disasm": "mov eax, 1"},
            {"offset": 0x1004, "disasm": "push rbx"},
            {"offset": 0x1008, "disasm": "call 0x2000"},
            {"offset": 0x100C, "disasm": "ret"},
        ]

        summary = analyzer._analyze_function_summary(0x1000, instructions)

        expect(summary["address"] == "0x1000")
        expect(set(summary["modified_registers"]) == {"eax", "rbx"})
        expect(summary["side_effects"] == [{"type": "call", "address": "0x1008", "instruction": "call 0x2000"}])
        expect(summary["return_values"] == [])
        expect(summary["parameters"] == [])
        expect(summary["read_globals"] == [])
        expect(summary["written_globals"] == [])

    def test_analyze_function_summary_ret_branch_records_return_value(self, analyzer):
        """Pin the ret-branch: when a 'ret' instruction also matches `mov X,`
        it records both a modified register and a return value."""
        summary = analyzer._analyze_function_summary(0x2000, [{"offset": 0x2000, "disasm": "mov r0, ret"}])

        expect(set(summary["modified_registers"]) == {"r0"})
        expect(summary["return_values"] == [{"register": "r0", "type": "return"}])


class TestMemoryFlowIntegration:
    @pytest.fixture
    def analyzer(self):
        return MemoryFlowAnalyzer()

    def test_analyze_complete_function(self, analyzer):
        instructions = [
            {"offset": 0x1000, "disasm": "push rbp"},
            {"offset": 0x1002, "disasm": "mov rbp, rsp"},
            {"offset": 0x1005, "disasm": "sub rsp, 0x10"},
            {"offset": 0x1009, "disasm": "mov eax, [rdi]"},
            {"offset": 0x100C, "disasm": "mov [rsp+8], eax"},
            {"offset": 0x100F, "disasm": "mov rsp, rbp"},
            {"offset": 0x1012, "disasm": "pop rbp"},
            {"offset": 0x1014, "disasm": "ret"},
        ]

        result = analyzer.analyze_function(instructions, 0x1000)

        expect(not ("memory_accesses" not in result))
        expect(not ("stack_frame" not in result))
        expect(not ("dependencies" not in result))
        expect(not ("aliases" not in result))


class TestMemoryAccessType:
    def test_access_types(self):
        expect(MemoryAccessType.READ.value == "read")
        expect(MemoryAccessType.WRITE.value == "write")
        expect(MemoryAccessType.READ_WRITE.value == "read_write")
        expect(MemoryAccessType.ALLOC.value == "alloc")
        expect(MemoryAccessType.FREE.value == "free")


class TestMemoryFlowWiring:
    """MemoryFlowAnalyzer wired onto BinaryAnalyzer and the public API."""

    def test_binary_analyzer_analyze_memory_flow_records_stack_access(self):
        binary_analyzer = importlib.import_module("r2morph.analysis.analyzer").BinaryAnalyzer
        in_memory_typed_binary = importlib.import_module("tests._doubles.in_memory_typed_binary").InMemoryTypedBinary

        binary = in_memory_typed_binary(
            disasm_by_addr={
                0x1000: [
                    {"offset": 0x1000, "disasm": "push rbp"},
                    {"offset": 0x1001, "disasm": "mov rbp, rsp"},
                    {"offset": 0x1004, "disasm": "mov [rbp-0x8], rax"},
                ]
            }
        )

        result = binary_analyzer(binary).analyze_memory_flow(0x1000)

        expect(not ("0x1004" not in result["memory_accesses"]))

    def test_memory_flow_analyzer_is_public_analysis_export(self):
        exported_memory_flow_analyzer = importlib.import_module("r2morph.analysis").MemoryFlowAnalyzer
        memory_flow_analyzer = importlib.import_module("r2morph.analysis.memory_flow").MemoryFlowAnalyzer

        expect(not (exported_memory_flow_analyzer is not memory_flow_analyzer))
