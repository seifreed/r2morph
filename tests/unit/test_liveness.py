"""
Unit tests for liveness analysis module.
"""

from r2morph.analysis.cfg import BasicBlock, BlockType, ControlFlowGraph
from r2morph.analysis.liveness import (
    InstructionLiveness,
    InterferenceGraph,
    LivenessAnalysis,
    LiveRange,
    Register,
)
from tests.utils.assertions import expect

_EXPECTED_IL_ADDRESS_4096 = 0x1000
_EXPECTED_LEN_ANALYZER_BLOCK_LIVE_IN_2 = 2
_EXPECTED_LEN_ANALYZER_BLOCK_LIVE_IN_4 = 4
_EXPECTED_LEN_ANALYZER_BLOCK_LIVE_OUT_2 = 2
_EXPECTED_LEN_ANALYZER_BLOCK_LIVE_OUT_4 = 4
_EXPECTED_LEN_D_USES_2 = 2
_EXPECTED_LEN_IL_LIVE_BEFORE_2 = 2
_EXPECTED_LEN_IL_USED_2 = 2
_EXPECTED_LEN_NEIGHBORS_2 = 2
_EXPECTED_LEN_NODES_3 = 3
_EXPECTED_LR_END_ADDRESS_4128 = 0x1020
_EXPECTED_LR_START_ADDRESS_4096 = 0x1000
_EXPECTED_R_SIZE_16 = 16
_EXPECTED_R_SIZE_32 = 32
_EXPECTED_R_SIZE_64 = 64
_EXPECTED_R_SIZE_8 = 8


def create_simple_cfg() -> ControlFlowGraph:
    """Create a simple CFG for liveness testing."""
    cfg = ControlFlowGraph(function_address=0x1000, function_name="simple")

    block = BasicBlock(
        address=0x1000,
        size=12,
        instructions=[
            {"offset": 0x1000, "type": "mov", "disasm": "mov eax, 1"},
            {"offset": 0x1005, "type": "mov", "disasm": "mov ebx, 2"},
            {"offset": 0x100A, "type": "add", "disasm": "add eax, ebx"},
        ],
        successors=[],
        predecessors=[],
        block_type=BlockType.NORMAL,
    )

    cfg.add_block(block)
    return cfg


def create_sequential_cfg() -> ControlFlowGraph:
    """Create a sequential CFG with multiple blocks."""
    cfg = ControlFlowGraph(function_address=0x2000, function_name="sequential")

    block1 = BasicBlock(
        address=0x2000,
        size=8,
        instructions=[
            {"offset": 0x2000, "type": "mov", "disasm": "mov eax, 5"},
            {"offset": 0x2004, "type": "mov", "disasm": "mov ebx, 10"},
        ],
        successors=[0x2010],
        predecessors=[],
        block_type=BlockType.NORMAL,
    )

    block2 = BasicBlock(
        address=0x2010,
        size=12,
        instructions=[
            {"offset": 0x2010, "type": "add", "disasm": "add eax, ebx"},
            {"offset": 0x2015, "type": "mov", "disasm": "mov ecx, eax"},
            {"offset": 0x201A, "type": "sub", "disasm": "sub ecx, 1"},
        ],
        successors=[],
        predecessors=[0x2000],
        block_type=BlockType.RETURN,
    )

    cfg.add_block(block1)
    cfg.add_block(block2)
    cfg.add_edge(0x2000, 0x2010)

    return cfg


def create_conditional_cfg() -> ControlFlowGraph:
    """Create a CFG with conditional branch."""
    cfg = ControlFlowGraph(function_address=0x3000, function_name="conditional")

    entry = BasicBlock(
        address=0x3000,
        size=8,
        instructions=[
            {"offset": 0x3000, "type": "mov", "disasm": "mov eax, [rbp+8]"},
            {"offset": 0x3004, "type": "test", "disasm": "test eax, eax"},
        ],
        successors=[0x3010, 0x3020],
        predecessors=[],
        block_type=BlockType.CONDITIONAL,
    )

    then_block = BasicBlock(
        address=0x3010,
        size=4,
        instructions=[
            {"offset": 0x3010, "type": "mov", "disasm": "mov ebx, 1"},
        ],
        successors=[0x3030],
        predecessors=[0x3000],
        block_type=BlockType.NORMAL,
    )

    else_block = BasicBlock(
        address=0x3020,
        size=4,
        instructions=[
            {"offset": 0x3020, "type": "mov", "disasm": "mov ebx, 0"},
        ],
        successors=[0x3030],
        predecessors=[0x3000],
        block_type=BlockType.NORMAL,
    )

    merge = BasicBlock(
        address=0x3030,
        size=4,
        instructions=[
            {"offset": 0x3030, "type": "mov", "disasm": "mov eax, ebx"},
        ],
        successors=[],
        predecessors=[0x3010, 0x3020],
        block_type=BlockType.RETURN,
    )

    cfg.add_block(entry)
    cfg.add_block(then_block)
    cfg.add_block(else_block)
    cfg.add_block(merge)
    cfg.add_edge(0x3000, 0x3010)
    cfg.add_edge(0x3000, 0x3020)
    cfg.add_edge(0x3010, 0x3030)
    cfg.add_edge(0x3020, 0x3030)

    return cfg


class TestLiveRange:
    """Tests for LiveRange class."""

    def test_live_range_creation(self):
        """Test live range creation."""
        reg = Register("eax", 32)
        lr = LiveRange(
            register=reg,
            start_address=0x1000,
            end_address=0x1020,
        )

        expect(lr.register == reg)
        expect(lr.start_address == _EXPECTED_LR_START_ADDRESS_4096)
        expect(lr.end_address == _EXPECTED_LR_END_ADDRESS_4128)

    def test_live_range_contains(self):
        """Test contains method."""
        reg = Register("ebx", 32)
        lr = LiveRange(
            register=reg,
            start_address=0x1000,
            end_address=0x1050,
        )

        expect(not (lr.contains(0x1000) is not True))
        expect(not (lr.contains(0x1025) is not True))
        expect(not (lr.contains(0x1050) is not True))
        expect(not (lr.contains(0x0999) is not False))
        expect(not (lr.contains(0x1051) is not False))

    def test_live_range_overlaps(self):
        """Test overlaps method."""
        reg1 = Register("eax", 32)
        reg2 = Register("ebx", 32)

        lr1 = LiveRange(register=reg1, start_address=0x1000, end_address=0x1020)
        lr2 = LiveRange(register=reg1, start_address=0x1010, end_address=0x1030)
        lr3 = LiveRange(register=reg1, start_address=0x1025, end_address=0x1050)

        expect(not (lr1.overlaps(lr2) is not True))
        expect(not (lr2.overlaps(lr1) is not True))
        expect(not (lr1.overlaps(lr3) is not False))

        lr4 = LiveRange(register=reg2, start_address=0x1000, end_address=0x1020)
        expect(not (lr1.overlaps(lr4) is not False))

    def test_live_range_to_dict(self):
        """Test to_dict method."""
        reg = Register("ecx", 32)
        lr = LiveRange(
            register=reg,
            start_address=0x1000,
            end_address=0x1050,
            definition_address=0x1000,
            use_addresses=[0x1020, 0x1040],
        )

        d = lr.to_dict()

        expect(d["register"] == "ecx")
        expect(not ("start" not in d))
        expect(not ("end" not in d))
        expect(not ("definition" not in d))
        expect(len(d["uses"]) == _EXPECTED_LEN_D_USES_2)


class TestInstructionLiveness:
    """Tests for InstructionLiveness class."""

    def test_instruction_liveness_creation(self):
        """Test instruction liveness creation."""
        il = InstructionLiveness(
            address=0x1000,
            instruction="mov eax, 1",
        )

        expect(il.address == _EXPECTED_IL_ADDRESS_4096)
        expect(il.instruction == "mov eax, 1")
        expect(len(il.live_before) == 0)
        expect(len(il.live_after) == 0)

    def test_instruction_liveness_sets(self):
        """Test liveness sets."""
        eax = Register("eax", 32)
        ebx = Register("ebx", 32)

        il = InstructionLiveness(
            address=0x1000,
            instruction="add eax, ebx",
            live_before={eax, ebx},
            live_after={eax},
            defined={eax},
            used={eax, ebx},
        )

        expect(len(il.live_before) == _EXPECTED_LEN_IL_LIVE_BEFORE_2)
        expect(len(il.live_after) == 1)
        expect(len(il.defined) == 1)
        expect(len(il.used) == _EXPECTED_LEN_IL_USED_2)

    def test_instruction_liveness_to_dict(self):
        """Test to_dict method."""
        eax = Register("eax", 32)

        il = InstructionLiveness(
            address=0x1000,
            instruction="mov eax, ebx",
            live_before={eax},
        )

        d = il.to_dict()

        expect(not ("eax" not in d["live_before"]))
        expect(d["instruction"] == "mov eax, ebx")


class TestInterferenceGraph:
    """Tests for InterferenceGraph class."""

    def test_graph_creation(self):
        """Test graph creation."""
        graph = InterferenceGraph()

        expect(len(graph.edges) == 0)

    def test_add_node(self):
        """Test adding nodes."""
        graph = InterferenceGraph()

        graph.add_node("eax")
        expect(not ("eax" not in graph.edges))

        graph.add_node("ebx")
        expect(not ("ebx" not in graph.edges))

    def test_add_edge(self):
        """Test adding edges."""
        graph = InterferenceGraph()

        graph.add_edge("eax", "ebx")

        expect(not ("eax" not in graph.edges))
        expect(not ("ebx" not in graph.edges))
        expect(not ("ebx" not in graph.edges["eax"]))
        expect(not ("eax" not in graph.edges["ebx"]))

    def test_interfere(self):
        """Test interfere method."""
        graph = InterferenceGraph()

        graph.add_edge("eax", "ebx")

        expect(not (graph.interfere("eax", "ebx") is not True))
        expect(not (graph.interfere("ebx", "eax") is not True))
        expect(not (graph.interfere("eax", "ecx") is not False))

    def test_get_neighbors(self):
        """Test get_neighbors method."""
        graph = InterferenceGraph()

        graph.add_edge("eax", "ebx")
        graph.add_edge("eax", "ecx")

        neighbors = graph.get_neighbors("eax")
        expect(not ("ebx" not in neighbors))
        expect(not ("ecx" not in neighbors))
        expect(len(neighbors) == _EXPECTED_LEN_NEIGHBORS_2)

    def test_get_nodes(self):
        """Test get_nodes method."""
        graph = InterferenceGraph()

        graph.add_node("eax")
        graph.add_node("ebx")
        graph.add_node("ecx")

        nodes = graph.get_nodes()
        expect(len(nodes) == _EXPECTED_LEN_NODES_3)
        expect(not ("eax" not in nodes))
        expect(not ("ebx" not in nodes))
        expect(not ("ecx" not in nodes))

    def test_to_dict(self):
        """Test to_dict method."""
        graph = InterferenceGraph()

        graph.add_edge("eax", "ebx")
        graph.add_edge("eax", "ecx")

        d = graph.to_dict()

        expect(not ("eax" not in d))
        expect(not ("ebx" not in d["eax"]))
        expect(not ("ecx" not in d["eax"]))


class TestLivenessAnalysis:
    """Tests for LivenessAnalysis class."""

    def test_analyzer_creation(self):
        """Test analyzer creation."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)

        expect(not (analyzer.cfg is not cfg))
        expect(len(analyzer._instruction_liveness) == 0)

    def test_compute_simple(self):
        """Test compute on simple CFG."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        expect(not (len(analyzer._instruction_liveness) <= 0))
        expect(not (len(analyzer._live_ranges) <= 0))

    def test_compute_block_liveness(self):
        """Test block-level liveness computation."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer._compute_block_liveness()

        expect(len(analyzer._block_live_in) == _EXPECTED_LEN_ANALYZER_BLOCK_LIVE_IN_2)
        expect(len(analyzer._block_live_out) == _EXPECTED_LEN_ANALYZER_BLOCK_LIVE_OUT_2)

    def test_compute_instruction_liveness(self):
        """Test instruction-level liveness computation."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer._compute_block_liveness()
        analyzer._compute_instruction_liveness()

        expect(not (len(analyzer._instruction_liveness) <= 0))

        for addr, il in analyzer._instruction_liveness.items():
            expect(isinstance(il, InstructionLiveness))
            expect(il.address == addr)

    def test_is_live_at(self):
        """Test is_live_at method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        eax = Register("eax", 32)

        result = analyzer.is_live_at(eax, 0x2000)
        expect(isinstance(result, bool))

    def test_get_live_registers(self):
        """Test get_live_registers method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        live = analyzer.get_live_registers(0x2000)

        expect(isinstance(live, set))

    def test_get_live_ranges(self):
        """Test get_live_ranges method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        all_ranges = analyzer.get_live_ranges()
        expect(isinstance(all_ranges, list))

        eax = Register("eax", 32)
        eax_ranges = analyzer.get_live_ranges(eax)
        expect(isinstance(eax_ranges, list))

    def test_get_instruction_liveness(self):
        """Test get_instruction_liveness method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        il = analyzer.get_instruction_liveness(0x2000)
        expect(il is None or isinstance(il, InstructionLiveness))

    def test_get_interference_graph(self):
        """Test get_interference_graph method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        graph = analyzer.get_interference_graph()
        expect(isinstance(graph, InterferenceGraph))

    def test_conditional_cfg(self):
        """Test analysis on conditional CFG."""
        cfg = create_conditional_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        expect(len(analyzer._block_live_in) == _EXPECTED_LEN_ANALYZER_BLOCK_LIVE_IN_4)
        expect(len(analyzer._block_live_out) == _EXPECTED_LEN_ANALYZER_BLOCK_LIVE_OUT_4)

    def test_register_extraction(self):
        """Test register extraction from instruction."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)

        regs = analyzer._parse_registers_from_string("mov eax, ebx")
        reg_names = {r.name for r in regs}
        expect(not ("eax" not in reg_names))
        expect(not ("ebx" not in reg_names))

        regs = analyzer._parse_registers_from_string("add rax, r8")
        reg_names = {r.name for r in regs}
        expect(not ("rax" not in reg_names))
        expect(not ("r8" not in reg_names))

    def test_read_modify_write_destination_is_live_before_instruction(self):
        """Read-modify-write arithmetic keeps its destination in the use set."""
        analyzer = LivenessAnalysis(create_simple_cfg())

        used = analyzer._extract_registers_used({"type": "add", "disasm": "add eax, ebx"})

        expect({register.name for register in used} == {"eax", "ebx"})

    def test_write_only_move_destination_is_not_live_before_instruction(self):
        """A move destination is overwritten without reading its previous value."""
        analyzer = LivenessAnalysis(create_simple_cfg())

        used = analyzer._extract_registers_used({"type": "mov", "disasm": "mov eax, ebx"})

        expect({register.name for register in used} == {"ebx"})

    def test_sysv_call_uses_rax_for_variadic_vector_count(self):
        """SysV calls consume al/rax for the variadic vector-argument count."""
        analyzer = LivenessAnalysis(create_simple_cfg())

        used = analyzer._extract_registers_used({"type": "call", "disasm": "call 0x2000"})

        expect("rax" in {register.name for register in used})

    def test_sysv_call_uses_vector_argument_registers(self):
        """SysV calls consume the eight vector argument register pairs."""
        analyzer = LivenessAnalysis(create_simple_cfg())

        used = analyzer._extract_registers_used({"type": "call", "disasm": "call 0x2000"})
        names = {register.name for register in used}

        expect({"xmm0", "xmm7", "ymm0", "ymm7"} <= names)

    def test_sysv_call_defines_all_caller_saved_vector_registers(self):
        """SysV calls clobber all XMM/YMM registers, including return vectors."""
        analyzer = LivenessAnalysis(create_simple_cfg())

        defined = analyzer._extract_registers_defined({"type": "call", "disasm": "call 0x2000"})
        names = {register.name for register in defined}

        expect({"xmm0", "xmm15", "ymm0", "ymm15"} <= names)

    def test_to_dict(self):
        """Test to_dict method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        d = analyzer.to_dict()

        expect(not ("instruction_liveness" not in d))
        expect(not ("live_ranges" not in d))
        expect(not ("interference_graph" not in d))


class TestLivenessWithRealInstructions:
    """Tests for liveness with realistic instruction patterns."""

    def test_register_sizes(self):
        """Test correct handling of register sizes."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)

        regs = analyzer._parse_registers_from_string("mov eax, [rax]")
        for r in regs:
            if r.name == "eax":
                expect(r.size == _EXPECTED_R_SIZE_32)
            expect(not (r.name == "rax" and r.size != _EXPECTED_R_SIZE_64))

    def test_8bit_registers(self):
        """Test handling of 8-bit registers."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)

        regs = analyzer._parse_registers_from_string("mov al, bl")
        reg_names = {r.name for r in regs}

        expect(not ("al" not in reg_names))
        expect(not ("bl" not in reg_names))

        for r in regs:
            expect(r.size == _EXPECTED_R_SIZE_8)

    def test_16bit_registers(self):
        """Test handling of 16-bit registers."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)

        regs = analyzer._parse_registers_from_string("mov ax, bx")
        reg_names = {r.name for r in regs}

        expect(not ("ax" not in reg_names))
        expect(not ("bx" not in reg_names))

        for r in regs:
            expect(r.size == _EXPECTED_R_SIZE_16)
