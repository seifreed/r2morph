"""
Unit tests for data flow analysis module.
"""

import pytest
from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph, BlockType
from r2morph.analysis.dataflow import (
    DataFlowAnalyzer,
    DataFlowResult,
    DataFlowDirection,
    Register,
    Definition,
    Use,
    DefUseChain,
)


def create_test_cfg() -> ControlFlowGraph:
    """Create a test CFG for data flow analysis."""
    cfg = ControlFlowGraph(function_address=0x1000, function_name="test_func")

    block1 = BasicBlock(
        address=0x1000,
        size=8,
        instructions=[
            {"offset": 0x1000, "type": "mov", "disasm": "mov eax, 1"},
            {"offset": 0x1005, "type": "mov", "disasm": "mov ebx, 2"},
        ],
        successors=[0x1010],
        predecessors=[],
        block_type=BlockType.NORMAL,
    )

    block2 = BasicBlock(
        address=0x1010,
        size=8,
        instructions=[
            {"offset": 0x1010, "type": "add", "disasm": "add eax, ebx"},
            {"offset": 0x1015, "type": "mov", "disasm": "mov ecx, eax"},
        ],
        successors=[0x1020],
        predecessors=[0x1000],
        block_type=BlockType.NORMAL,
    )

    block3 = BasicBlock(
        address=0x1020,
        size=4,
        instructions=[
            {"offset": 0x1020, "type": "ret", "disasm": "ret"},
        ],
        successors=[],
        predecessors=[0x1010],
        block_type=BlockType.RETURN,
    )

    cfg.add_block(block1)
    cfg.add_block(block2)
    cfg.add_block(block3)

    cfg.add_edge(0x1000, 0x1010)
    cfg.add_edge(0x1010, 0x1020)

    return cfg


def create_branching_cfg() -> ControlFlowGraph:
    """Create a test CFG with branching."""
    cfg = ControlFlowGraph(function_address=0x2000, function_name="branch_func")

    entry = BasicBlock(
        address=0x2000,
        size=8,
        instructions=[
            {"offset": 0x2000, "type": "mov", "disasm": "mov eax, [rbp+8]"},
            {"offset": 0x2005, "type": "cmp", "disasm": "cmp eax, 0"},
        ],
        successors=[0x2010, 0x2020],
        predecessors=[],
        block_type=BlockType.CONDITIONAL,
    )

    true_block = BasicBlock(
        address=0x2010,
        size=4,
        instructions=[
            {"offset": 0x2010, "type": "mov", "disasm": "mov ebx, 1"},
        ],
        successors=[0x2030],
        predecessors=[0x2000],
        block_type=BlockType.NORMAL,
    )

    false_block = BasicBlock(
        address=0x2020,
        size=4,
        instructions=[
            {"offset": 0x2020, "type": "mov", "disasm": "mov ebx, 2"},
        ],
        successors=[0x2030],
        predecessors=[0x2000],
        block_type=BlockType.NORMAL,
    )

    merge = BasicBlock(
        address=0x2030,
        size=4,
        instructions=[
            {"offset": 0x2030, "type": "add", "disasm": "add ebx, eax"},
            {"offset": 0x2035, "type": "ret", "disasm": "ret"},
        ],
        successors=[],
        predecessors=[0x2010, 0x2020],
        block_type=BlockType.RETURN,
    )

    cfg.add_block(entry)
    cfg.add_block(true_block)
    cfg.add_block(false_block)
    cfg.add_block(merge)

    cfg.add_edge(0x2000, 0x2010)
    cfg.add_edge(0x2000, 0x2020)
    cfg.add_edge(0x2010, 0x2030)
    cfg.add_edge(0x2020, 0x2030)

    return cfg


def create_loop_cfg() -> ControlFlowGraph:
    """Create a test CFG with a loop."""
    cfg = ControlFlowGraph(function_address=0x3000, function_name="loop_func")

    header = BasicBlock(
        address=0x3000,
        size=8,
        instructions=[
            {"offset": 0x3000, "type": "mov", "disasm": "mov ecx, 10"},
            {"offset": 0x3005, "type": "xor", "disasm": "xor eax, eax"},
        ],
        successors=[0x3010],
        predecessors=[0x3030],
        block_type=BlockType.NORMAL,
    )

    loop_header = BasicBlock(
        address=0x3010,
        size=4,
        instructions=[
            {"offset": 0x3010, "type": "test", "disasm": "test ecx, ecx"},
        ],
        successors=[0x3020, 0x3040],
        predecessors=[0x3000],
        block_type=BlockType.CONDITIONAL,
    )

    loop_body = BasicBlock(
        address=0x3020,
        size=8,
        instructions=[
            {"offset": 0x3020, "type": "add", "disasm": "add eax, ecx"},
            {"offset": 0x3025, "type": "dec", "disasm": "dec ecx"},
        ],
        successors=[0x3030],
        predecessors=[0x3010],
        block_type=BlockType.NORMAL,
    )

    loop_back = BasicBlock(
        address=0x3030,
        size=4,
        instructions=[
            {"offset": 0x3030, "type": "jmp", "disasm": "jmp 0x3010"},
        ],
        successors=[0x3010],
        predecessors=[0x3020],
        block_type=BlockType.NORMAL,
    )

    exit_block = BasicBlock(
        address=0x3040,
        size=4,
        instructions=[
            {"offset": 0x3040, "type": "ret", "disasm": "ret"},
        ],
        successors=[],
        predecessors=[0x3010],
        block_type=BlockType.RETURN,
    )

    cfg.add_block(header)
    cfg.add_block(loop_header)
    cfg.add_block(loop_body)
    cfg.add_block(loop_back)
    cfg.add_block(exit_block)

    cfg.add_edge(0x3000, 0x3010)
    cfg.add_edge(0x3010, 0x3020)
    cfg.add_edge(0x3010, 0x3040)
    cfg.add_edge(0x3020, 0x3030)
    cfg.add_edge(0x3030, 0x3010)

    return cfg


class TestRegister:
    """Tests for Register class."""

    def test_register_creation(self):
        """Test basic register creation."""
        reg = Register("rax", 64)
        assert reg.name == "rax"
        assert reg.size == 64
        assert reg.is_float is False

    def test_register_repr(self):
        """Test register string representation."""
        reg = Register("eax", 32)
        assert repr(reg) == "eax"

    def test_register_hash_equality(self):
        """Test register hashing and equality."""
        reg1 = Register("rax", 64)
        reg2 = Register("rax", 64)
        reg3 = Register("eax", 32)

        assert hash(reg1) == hash(reg2)
        assert reg1 == reg2
        assert reg1 != reg3

    def test_register_aliases_x86_64(self):
        """Test x86-64 register alias extraction."""
        reg = Register("rax", 64)
        aliases = reg.aliases()

        alias_names = {r.name for r in aliases}
        assert "rax" in alias_names
        assert "eax" in alias_names
        assert "ax" in alias_names
        assert "al" in alias_names

    def test_register_aliases_32bit(self):
        """Test 32-bit register aliases."""
        reg = Register("ebx", 32)
        aliases = reg.aliases()

        alias_names = {r.name for r in aliases}
        assert "rbx" in alias_names
        assert "ebx" in alias_names
        assert "bx" in alias_names
        assert "bl" in alias_names


class TestDefinition:
    """Tests for Definition class."""

    def test_definition_creation(self):
        """Test basic definition creation."""
        reg = Register("eax", 32)
        defn = Definition(address=0x1000, register=reg, instruction="mov eax, 1")

        assert defn.address == 0x1000
        assert defn.register == reg
        assert defn.instruction == "mov eax, 1"

    def test_definition_repr(self):
        """Test definition string representation."""
        reg = Register("ebx", 32)
        defn = Definition(address=0x2000, register=reg)

        assert "0x2000" in repr(defn)
        assert "ebx" in repr(defn)

    def test_definition_hash_equality(self):
        """Test definition hashing and equality."""
        reg1 = Register("ecx", 32)
        reg2 = Register("ecx", 32)

        defn1 = Definition(address=0x1000, register=reg1)
        defn2 = Definition(address=0x1000, register=reg2)
        defn3 = Definition(address=0x2000, register=reg1)

        assert hash(defn1) == hash(defn2)
        assert defn1 == defn2
        assert defn1 != defn3


class TestUse:
    """Tests for Use class."""

    def test_use_creation(self):
        """Test basic use creation."""
        reg = Register("eax", 32)
        use = Use(address=0x1005, register=reg, instruction="add eax, ebx")

        assert use.address == 0x1005
        assert use.register == reg
        assert use.instruction == "add eax, ebx"

    def test_use_repr(self):
        """Test use string representation."""
        reg = Register("rdx", 64)
        use = Use(address=0x3000, register=reg)

        assert "0x3000" in repr(use)
        assert "rdx" in repr(use)


class TestDefUseChain:
    """Tests for DefUseChain class."""

    def test_chain_creation(self):
        """Test def-use chain creation."""
        reg = Register("eax", 32)
        defn = Definition(address=0x1000, register=reg)
        use1 = Use(address=0x1010, register=reg)
        use2 = Use(address=0x1020, register=reg)

        chain = DefUseChain(definition=defn, uses=[use1, use2], register=reg)

        assert chain.definition == defn
        assert len(chain.uses) == 2
        assert chain.register == reg

    def test_chain_add_use(self):
        """Test adding uses to chain."""
        reg = Register("ebx", 32)
        defn = Definition(address=0x1000, register=reg)
        chain = DefUseChain(definition=defn, register=reg)

        use = Use(address=0x1010, register=reg)
        chain.add_use(use)

        assert len(chain.uses) == 1
        assert chain.uses[0] == use

    def test_chain_live_range(self):
        """Test live range calculation."""
        reg = Register("ecx", 32)
        defn = Definition(address=0x1000, register=reg)
        use1 = Use(address=0x1010, register=reg)
        use2 = Use(address=0x1050, register=reg)

        chain = DefUseChain(definition=defn, uses=[use1, use2], register=reg)

        assert chain.live_range == (0x1000, 0x1050)

    def test_chain_is_live_at(self):
        """Test is_live_at check."""
        reg = Register("edx", 32)
        defn = Definition(address=0x1000, register=reg)
        use = Use(address=0x1020, register=reg)

        chain = DefUseChain(definition=defn, uses=[use], register=reg)

        assert chain.is_live_at(0x1000) is True
        assert chain.is_live_at(0x1010) is True
        assert chain.is_live_at(0x1020) is True
        assert chain.is_live_at(0x1030) is False


class TestDataFlowResult:
    """Tests for DataFlowResult class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = DataFlowResult()

        assert result.live_in == {}
        assert result.live_out == {}
        assert result.reaching_in == {}
        assert result.reaching_out == {}
        assert result.def_use_chains == []

    def test_result_get_live_registers(self):
        """Test get_live_registers method."""
        result = DataFlowResult()
        reg1 = Register("eax", 32)
        reg2 = Register("ebx", 32)

        result.live_in[0x1000] = {reg1, reg2}
        result.live_in[0x2000] = {reg1}

        live_at_1000 = result.get_live_registers(0x1000)
        assert len(live_at_1000) == 2

        live_at_2000 = result.get_live_registers(0x2000)
        assert len(live_at_2000) == 1

        live_at_3000 = result.get_live_registers(0x3000)
        assert len(live_at_3000) == 0

    def test_result_is_register_live(self):
        """Test is_register_live method."""
        result = DataFlowResult()
        reg = Register("eax", 32)

        result.live_in[0x1000] = {reg}

        assert result.is_register_live(0x1000, reg) is True
        assert result.is_register_live(0x1000, Register("ebx", 32)) is False

    def test_result_get_reaching_definitions(self):
        """Test get_reaching_definitions method."""
        result = DataFlowResult()
        reg = Register("eax", 32)
        defn = Definition(address=0x1000, register=reg)

        result.reaching_in[0x1010] = {defn}

        reaching = result.get_reaching_definitions(0x1010)
        assert len(reaching) == 1
        assert defn in reaching

        reaching_empty = result.get_reaching_definitions(0x2000)
        assert len(reaching_empty) == 0


class TestDataFlowAnalyzer:
    """Tests for DataFlowAnalyzer class."""

    def test_analyzer_creation(self):
        """Test analyzer initialization."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)

        assert analyzer.cfg is cfg
        assert isinstance(analyzer._result, DataFlowResult)

    def test_analyze_basic(self):
        """Test basic analysis."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        result = analyzer.analyze()

        assert isinstance(result, DataFlowResult)
        assert len(result.live_in) > 0
        assert len(result.live_out) > 0

    def test_analyze_liveness(self):
        """Test liveness computation."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        analyzer._compute_liveness()

        assert len(analyzer._result.live_in) == 3
        assert len(analyzer._result.live_out) == 3

    def test_analyze_reaching_definitions(self):
        """Test reaching definitions computation."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        analyzer._compute_reaching_definitions()

        assert len(analyzer._result.reaching_in) == 3
        assert len(analyzer._result.reaching_out) == 3

    def test_get_block_use(self):
        """Test extracting registers used in block."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)

        block = cfg.blocks[0x1010]
        used = analyzer._get_block_use(block)

        assert len(used) > 0
        reg_names = {r.name for r in used}
        assert "eax" in reg_names or "ebx" in reg_names

    def test_get_block_def(self):
        """Test extracting registers defined in block."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)

        block = cfg.blocks[0x1000]
        defined = analyzer._get_block_def(block)

        assert len(defined) > 0
        reg_names = {r.name for r in defined}
        assert "eax" in reg_names or "ebx" in reg_names

    def test_extract_registers_from_operand(self):
        """Test register extraction from operands."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)

        regs = analyzer._extract_registers_from_operand("mov eax, ebx")
        reg_names = {r.name for r in regs}
        assert "eax" in reg_names
        assert "ebx" in reg_names

        regs = analyzer._extract_registers_from_operand("add rax, r8")
        reg_names = {r.name for r in regs}
        assert "rax" in reg_names
        assert "r8" in reg_names

    def test_is_safe_to_mutate(self):
        """Test mutation safety check."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        analyzer.analyze()

        is_safe, reason = analyzer.is_safe_to_mutate(0x1010, "register_substitution")
        assert isinstance(is_safe, bool)
        assert isinstance(reason, str)

    def test_branching_cfg(self):
        """Test analysis on branching CFG."""
        cfg = create_branching_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        result = analyzer.analyze()

        assert len(result.live_in) == 4
        assert len(result.live_out) == 4

    def test_loop_cfg(self):
        """Test analysis on loop CFG."""
        cfg = create_loop_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        result = analyzer.analyze()

        assert len(result.live_in) == 5
        assert len(result.live_out) == 5


class TestDataFlowDirection:
    """Tests for DataFlowDirection enum."""

    def test_direction_values(self):
        """Test direction enum values."""
        assert DataFlowDirection.FORWARD.value == "forward"
        assert DataFlowDirection.BACKWARD.value == "backward"
