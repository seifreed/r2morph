"""
Unit tests for memory flow analysis.
"""

import pytest

from r2morph.analysis.memory_flow import (
    MemoryAccessType,
    MemoryLocation,
    MemoryAccess,
    MemoryDependency,
    MemoryFlowAnalyzer,
    InterproceduralDataFlowAnalyzer,
)


class TestMemoryLocation:
    def test_memory_location_creation(self):
        loc = MemoryLocation(address=0x1000, size=8)
        assert loc.address == 0x1000
        assert loc.size == 8
        assert loc.name == ""
        assert loc.location_type == "unknown"

    def test_memory_location_with_name(self):
        loc = MemoryLocation(address=0x1000, size=4, name="buffer")
        assert loc.name == "buffer"

    def test_memory_location_repr(self):
        loc = MemoryLocation(address=0x1000, size=4, name="var_x")
        assert "0x1000" in repr(loc)
        assert "var_x" in repr(loc)

    def test_memory_location_hash(self):
        loc1 = MemoryLocation(address=0x1000, size=8)
        loc2 = MemoryLocation(address=0x1000, size=8)
        loc3 = MemoryLocation(address=0x1000, size=4)

        assert hash(loc1) == hash(loc2)
        assert hash(loc1) != hash(loc3)

    def test_memory_location_overlaps(self):
        loc1 = MemoryLocation(address=0x1000, size=8)
        loc2 = MemoryLocation(address=0x1004, size=8)
        loc3 = MemoryLocation(address=0x1010, size=4)

        assert loc1.overlaps(loc2)
        assert loc2.overlaps(loc1)
        assert not loc1.overlaps(loc3)

    def test_memory_location_to_dict(self):
        loc = MemoryLocation(address=0x1000, size=8, name="test", location_type="stack")
        d = loc.to_dict()
        assert d["address"] == "0x1000"
        assert d["size"] == 8
        assert d["name"] == "test"
        assert d["type"] == "stack"


class TestMemoryAccess:
    def test_memory_access_creation(self):
        loc = MemoryLocation(address=0x1000, size=4)
        access = MemoryAccess(
            address=0x500,
            location=loc,
            access_type=MemoryAccessType.READ,
        )
        assert access.address == 0x500
        assert access.access_type == MemoryAccessType.READ

    def test_memory_access_write(self):
        loc = MemoryLocation(address=0x2000, size=8)
        access = MemoryAccess(
            address=0x100,
            location=loc,
            access_type=MemoryAccessType.WRITE,
            instruction="mov [rax], rbx",
        )
        assert access.access_type == MemoryAccessType.WRITE
        assert "mov" in access.instruction

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
        assert "0x500" in d["instruction_address"]
        assert d["access_type"] == "read"
        assert "eax" in d["registers"]


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
        assert dep.dependency_type == "flow"
        assert not dep.is_alias

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
        assert dep.is_alias

    def test_memory_dependency_to_dict(self):
        loc = MemoryLocation(address=0x1000, size=4)
        access1 = MemoryAccess(address=0x100, location=loc, access_type=MemoryAccessType.WRITE)
        access2 = MemoryAccess(address=0x200, location=loc, access_type=MemoryAccessType.READ)

        dep = MemoryDependency(source=access1, target=access2, dependency_type="anti")
        d = dep.to_dict()
        assert d["type"] == "anti"


class TestMemoryFlowAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return MemoryFlowAnalyzer()

    def test_analyzer_initialization(self, analyzer):
        assert len(analyzer._accesses) == 0
        assert len(analyzer._locations) == 0

    def test_analyze_function_empty(self, analyzer):
        instructions = []
        result = analyzer.analyze_function(instructions, 0x1000)

        assert "memory_accesses" in result
        assert "locations" in result
        assert "dependencies" in result

    def test_analyze_function_simple_mov(self, analyzer):
        instructions = [
            {"offset": 0x1000, "disasm": "mov eax, [0x2000]"},
            {"offset": 0x1005, "disasm": "mov [0x3000], eax"},
        ]

        result = analyzer.analyze_function(instructions, 0x1000)

        assert "memory_accesses" in result
        assert "stack_frame" in result

    def test_analyze_function_push_pop(self, analyzer):
        instructions = [
            {"offset": 0x1000, "disasm": "push rax"},
            {"offset": 0x1002, "disasm": "pop rbx"},
        ]

        result = analyzer.analyze_function(instructions, 0x1000)

        assert "memory_accesses" in result
        assert "stack_frame" in result
        assert len(result["stack_frame"]["saved_regs"]) > 0

    def test_analyze_stack_frame(self, analyzer):
        instructions = [
            {"offset": 0x1000, "disasm": "push rbp"},
            {"offset": 0x1002, "disasm": "mov rbp, rsp"},
            {"offset": 0x1005, "disasm": "sub rsp, 0x20"},
            {"offset": 0x1009, "disasm": "mov [rbp-8], eax"},
        ]

        frame = analyzer._analyze_stack_frame(instructions, 0x1000)

        assert "local_vars" in frame
        assert "frame_size" in frame
        assert frame["frame_size"] > 0

    def test_extract_access_size_byte(self, analyzer):
        size = analyzer._extract_access_size("movzx eax, byte ptr [ebx]")
        assert size == 1

    def test_extract_access_size_word(self, analyzer):
        size = analyzer._extract_access_size("movzx eax, word ptr [ebx]")
        assert size == 2

    def test_extract_access_size_dword(self, analyzer):
        size = analyzer._extract_access_size("mov eax, [ebx]")
        assert size == 4

    def test_extract_access_size_qword(self, analyzer):
        size = analyzer._extract_access_size("mov rax, [rbx]")
        assert size == 8

    def test_extract_access_size_xmm(self, analyzer):
        size = analyzer._extract_access_size("movdqu xmm0, [rbx]")
        assert size == 16

    def test_extract_arm_access_size_byte(self, analyzer):
        size = analyzer._extract_arm_access_size("ldrb w0, [x1]")
        assert size == 1

    def test_extract_arm_access_size_word(self, analyzer):
        size = analyzer._extract_arm_access_size("ldrh w0, [x1]")
        assert size == 2

    def test_extract_arm_access_size_dword(self, analyzer):
        size = analyzer._extract_arm_access_size("ldr w0, [x1]")
        assert size == 4

    def test_compute_dependencies_empty(self, analyzer):
        deps = analyzer._compute_dependencies()
        assert deps == []

    def test_detect_aliases_empty(self, analyzer):
        aliases = analyzer._detect_aliases()
        assert aliases == {}

    def test_analyze_function_arm_str(self, analyzer):
        instructions = [
            {"offset": 0x1000, "disasm": "str x0, [sp, #8]"},
        ]

        result = analyzer.analyze_function(instructions, 0x1000)

        assert "memory_accesses" in result


class TestInterproceduralDataFlowAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return InterproceduralDataFlowAnalyzer()

    def test_analyzer_initialization(self, analyzer):
        assert len(analyzer._function_summaries) == 0
        assert len(analyzer._call_graph) == 0

    def test_analyze_program_basic(self, analyzer):
        functions = [
            {"offset": 0x1000, "instructions": [{"offset": 0x1000, "disasm": "mov eax, 1"}]},
        ]
        call_graph = {0x1000: []}

        result = analyzer.analyze_program(functions, call_graph)

        assert "function_summaries" in result
        assert "call_graph" in result

    def test_analyze_program_with_calls(self, analyzer):
        functions = [
            {"offset": 0x1000, "instructions": [{"offset": 0x1000, "disasm": "call 0x2000"}]},
            {"offset": 0x2000, "instructions": [{"offset": 0x2000, "disasm": "ret"}]},
        ]
        call_graph = {0x1000: [0x2000], 0x2000: []}

        result = analyzer.analyze_program(functions, call_graph)

        assert len(result["function_summaries"]) == 2


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

        assert "memory_accesses" in result
        assert "stack_frame" in result
        assert "dependencies" in result
        assert "aliases" in result


class TestMemoryAccessType:
    def test_access_types(self):
        assert MemoryAccessType.READ.value == "read"
        assert MemoryAccessType.WRITE.value == "write"
        assert MemoryAccessType.READ_WRITE.value == "read_write"
        assert MemoryAccessType.ALLOC.value == "alloc"
        assert MemoryAccessType.FREE.value == "free"
