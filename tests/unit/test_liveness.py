"""
Unit tests for liveness analysis module.
"""

import pytest
from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph, BlockType
from r2morph.analysis.liveness import (
    LivenessAnalysis,
    LiveRange,
    InstructionLiveness,
    InterferenceGraph,
    Register,
)


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

        assert lr.register == reg
        assert lr.start_address == 0x1000
        assert lr.end_address == 0x1020

    def test_live_range_contains(self):
        """Test contains method."""
        reg = Register("ebx", 32)
        lr = LiveRange(
            register=reg,
            start_address=0x1000,
            end_address=0x1050,
        )

        assert lr.contains(0x1000) is True
        assert lr.contains(0x1025) is True
        assert lr.contains(0x1050) is True
        assert lr.contains(0x0999) is False
        assert lr.contains(0x1051) is False

    def test_live_range_overlaps(self):
        """Test overlaps method."""
        reg1 = Register("eax", 32)
        reg2 = Register("ebx", 32)

        lr1 = LiveRange(register=reg1, start_address=0x1000, end_address=0x1020)
        lr2 = LiveRange(register=reg1, start_address=0x1010, end_address=0x1030)
        lr3 = LiveRange(register=reg1, start_address=0x1025, end_address=0x1050)

        assert lr1.overlaps(lr2) is True
        assert lr2.overlaps(lr1) is True
        assert lr1.overlaps(lr3) is False

        lr4 = LiveRange(register=reg2, start_address=0x1000, end_address=0x1020)
        assert lr1.overlaps(lr4) is False

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

        assert d["register"] == "ecx"
        assert "start" in d
        assert "end" in d
        assert "definition" in d
        assert len(d["uses"]) == 2


class TestInstructionLiveness:
    """Tests for InstructionLiveness class."""

    def test_instruction_liveness_creation(self):
        """Test instruction liveness creation."""
        il = InstructionLiveness(
            address=0x1000,
            instruction="mov eax, 1",
        )

        assert il.address == 0x1000
        assert il.instruction == "mov eax, 1"
        assert len(il.live_before) == 0
        assert len(il.live_after) == 0

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

        assert len(il.live_before) == 2
        assert len(il.live_after) == 1
        assert len(il.defined) == 1
        assert len(il.used) == 2

    def test_instruction_liveness_to_dict(self):
        """Test to_dict method."""
        eax = Register("eax", 32)

        il = InstructionLiveness(
            address=0x1000,
            instruction="mov eax, ebx",
            live_before={eax},
        )

        d = il.to_dict()

        assert "eax" in d["live_before"]
        assert d["instruction"] == "mov eax, ebx"


class TestInterferenceGraph:
    """Tests for InterferenceGraph class."""

    def test_graph_creation(self):
        """Test graph creation."""
        graph = InterferenceGraph()

        assert len(graph.edges) == 0

    def test_add_node(self):
        """Test adding nodes."""
        graph = InterferenceGraph()

        graph.add_node("eax")
        assert "eax" in graph.edges

        graph.add_node("ebx")
        assert "ebx" in graph.edges

    def test_add_edge(self):
        """Test adding edges."""
        graph = InterferenceGraph()

        graph.add_edge("eax", "ebx")

        assert "eax" in graph.edges
        assert "ebx" in graph.edges
        assert "ebx" in graph.edges["eax"]
        assert "eax" in graph.edges["ebx"]

    def test_interfere(self):
        """Test interfere method."""
        graph = InterferenceGraph()

        graph.add_edge("eax", "ebx")

        assert graph.interfere("eax", "ebx") is True
        assert graph.interfere("ebx", "eax") is True
        assert graph.interfere("eax", "ecx") is False

    def test_get_neighbors(self):
        """Test get_neighbors method."""
        graph = InterferenceGraph()

        graph.add_edge("eax", "ebx")
        graph.add_edge("eax", "ecx")

        neighbors = graph.get_neighbors("eax")
        assert "ebx" in neighbors
        assert "ecx" in neighbors
        assert len(neighbors) == 2

    def test_get_nodes(self):
        """Test get_nodes method."""
        graph = InterferenceGraph()

        graph.add_node("eax")
        graph.add_node("ebx")
        graph.add_node("ecx")

        nodes = graph.get_nodes()
        assert len(nodes) == 3
        assert "eax" in nodes
        assert "ebx" in nodes
        assert "ecx" in nodes

    def test_to_dict(self):
        """Test to_dict method."""
        graph = InterferenceGraph()

        graph.add_edge("eax", "ebx")
        graph.add_edge("eax", "ecx")

        d = graph.to_dict()

        assert "eax" in d
        assert "ebx" in d["eax"]
        assert "ecx" in d["eax"]


class TestLivenessAnalysis:
    """Tests for LivenessAnalysis class."""

    def test_analyzer_creation(self):
        """Test analyzer creation."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)

        assert analyzer.cfg is cfg
        assert len(analyzer._instruction_liveness) == 0

    def test_compute_simple(self):
        """Test compute on simple CFG."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        assert len(analyzer._instruction_liveness) > 0
        assert len(analyzer._live_ranges) > 0

    def test_compute_block_liveness(self):
        """Test block-level liveness computation."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer._compute_block_liveness()

        assert len(analyzer._block_live_in) == 2
        assert len(analyzer._block_live_out) == 2

    def test_compute_instruction_liveness(self):
        """Test instruction-level liveness computation."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer._compute_block_liveness()
        analyzer._compute_instruction_liveness()

        assert len(analyzer._instruction_liveness) > 0

        for addr, il in analyzer._instruction_liveness.items():
            assert isinstance(il, InstructionLiveness)
            assert il.address == addr

    def test_is_live_at(self):
        """Test is_live_at method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        eax = Register("eax", 32)

        result = analyzer.is_live_at(eax, 0x2000)
        assert isinstance(result, bool)

    def test_get_live_registers(self):
        """Test get_live_registers method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        live = analyzer.get_live_registers(0x2000)

        assert isinstance(live, set)

    def test_get_live_ranges(self):
        """Test get_live_ranges method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        all_ranges = analyzer.get_live_ranges()
        assert isinstance(all_ranges, list)

        eax = Register("eax", 32)
        eax_ranges = analyzer.get_live_ranges(eax)
        assert isinstance(eax_ranges, list)

    def test_get_instruction_liveness(self):
        """Test get_instruction_liveness method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        il = analyzer.get_instruction_liveness(0x2000)
        assert il is None or isinstance(il, InstructionLiveness)

    def test_get_interference_graph(self):
        """Test get_interference_graph method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        graph = analyzer.get_interference_graph()
        assert isinstance(graph, InterferenceGraph)

    def test_conditional_cfg(self):
        """Test analysis on conditional CFG."""
        cfg = create_conditional_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        assert len(analyzer._block_live_in) == 4
        assert len(analyzer._block_live_out) == 4

    def test_register_extraction(self):
        """Test register extraction from instruction."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)

        regs = analyzer._parse_registers_from_string("mov eax, ebx")
        reg_names = {r.name for r in regs}
        assert "eax" in reg_names
        assert "ebx" in reg_names

        regs = analyzer._parse_registers_from_string("add rax, r8")
        reg_names = {r.name for r in regs}
        assert "rax" in reg_names
        assert "r8" in reg_names

    def test_to_dict(self):
        """Test to_dict method."""
        cfg = create_sequential_cfg()
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()

        d = analyzer.to_dict()

        assert "instruction_liveness" in d
        assert "live_ranges" in d
        assert "interference_graph" in d


class TestLivenessWithRealInstructions:
    """Tests for liveness with realistic instruction patterns."""

    def test_register_sizes(self):
        """Test correct handling of register sizes."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)

        regs = analyzer._parse_registers_from_string("mov eax, [rax]")
        for r in regs:
            if r.name == "eax":
                assert r.size == 32
            elif r.name == "rax":
                assert r.size == 64

    def test_8bit_registers(self):
        """Test handling of 8-bit registers."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)

        regs = analyzer._parse_registers_from_string("mov al, bl")
        reg_names = {r.name for r in regs}

        assert "al" in reg_names
        assert "bl" in reg_names

        for r in regs:
            assert r.size == 8

    def test_16bit_registers(self):
        """Test handling of 16-bit registers."""
        cfg = create_simple_cfg()
        analyzer = LivenessAnalysis(cfg)

        regs = analyzer._parse_registers_from_string("mov ax, bx")
        reg_names = {r.name for r in regs}

        assert "ax" in reg_names
        assert "bx" in reg_names

        for r in regs:
            assert r.size == 16
