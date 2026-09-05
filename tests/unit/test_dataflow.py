"""
Unit tests for data flow analysis module.
"""

from r2morph.analysis.cfg import BasicBlock, BlockType, ControlFlowGraph
from r2morph.analysis.dataflow import (
    DataFlowAnalyzer,
    DataFlowDirection,
    DataFlowResult,
    Definition,
    DefUseChain,
    Register,
    Use,
)
from tests.utils.assertions import expect

_EXPECTED_DEFN_ADDRESS_4096 = 0x1000
_EXPECTED_LEN_ANALYZER_RESULT_LIVE_IN_3 = 3
_EXPECTED_LEN_ANALYZER_RESULT_LIVE_OUT_3 = 3
_EXPECTED_LEN_ANALYZER_RESULT_REACHING_IN_3 = 3
_EXPECTED_LEN_ANALYZER_RESULT_REACHING_OUT_3 = 3
_EXPECTED_LEN_CHAIN_USES_2 = 2
_EXPECTED_LEN_LIVE_AT_1000_2 = 2
_EXPECTED_LEN_RESULT_LIVE_IN_4 = 4
_EXPECTED_LEN_RESULT_LIVE_IN_5 = 5
_EXPECTED_LEN_RESULT_LIVE_OUT_4 = 4
_EXPECTED_LEN_RESULT_LIVE_OUT_5 = 5
_EXPECTED_REG_SIZE_64 = 64
_EXPECTED_USE_ADDRESS_4101 = 0x1005


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
        expect(reg.name == "rax")
        expect(reg.size == _EXPECTED_REG_SIZE_64)
        expect(not (reg.is_float is not False))

    def test_register_repr(self):
        """Test register string representation."""
        reg = Register("eax", 32)
        expect(repr(reg) == "eax")

    def test_register_hash_equality(self):
        """Test register hashing and equality."""
        reg1 = Register("rax", 64)
        reg2 = Register("rax", 64)
        reg3 = Register("eax", 32)

        expect(hash(reg1) == hash(reg2))
        expect(reg1 == reg2)
        expect(reg1 != reg3)

    def test_register_aliases_x86_64(self):
        """Test x86-64 register alias extraction."""
        reg = Register("rax", 64)
        aliases = reg.aliases()

        alias_names = {r.name for r in aliases}
        expect(not ("rax" not in alias_names))
        expect(not ("eax" not in alias_names))
        expect(not ("ax" not in alias_names))
        expect(not ("al" not in alias_names))

    def test_register_aliases_32bit(self):
        """Test 32-bit register aliases."""
        reg = Register("ebx", 32)
        aliases = reg.aliases()

        alias_names = {r.name for r in aliases}
        expect(not ("rbx" not in alias_names))
        expect(not ("ebx" not in alias_names))
        expect(not ("bx" not in alias_names))
        expect(not ("bl" not in alias_names))


class TestDefinition:
    """Tests for Definition class."""

    def test_definition_creation(self):
        """Test basic definition creation."""
        reg = Register("eax", 32)
        defn = Definition(address=0x1000, register=reg, instruction="mov eax, 1")

        expect(defn.address == _EXPECTED_DEFN_ADDRESS_4096)
        expect(defn.register == reg)
        expect(defn.instruction == "mov eax, 1")

    def test_definition_repr(self):
        """Test definition string representation."""
        reg = Register("ebx", 32)
        defn = Definition(address=0x2000, register=reg)

        expect(not ("0x2000" not in repr(defn)))
        expect(not ("ebx" not in repr(defn)))

    def test_definition_hash_equality(self):
        """Test definition hashing and equality."""
        reg1 = Register("ecx", 32)
        reg2 = Register("ecx", 32)

        defn1 = Definition(address=0x1000, register=reg1)
        defn2 = Definition(address=0x1000, register=reg2)
        defn3 = Definition(address=0x2000, register=reg1)

        expect(hash(defn1) == hash(defn2))
        expect(defn1 == defn2)
        expect(defn1 != defn3)


class TestUse:
    """Tests for Use class."""

    def test_use_creation(self):
        """Test basic use creation."""
        reg = Register("eax", 32)
        use = Use(address=0x1005, register=reg, instruction="add eax, ebx")

        expect(use.address == _EXPECTED_USE_ADDRESS_4101)
        expect(use.register == reg)
        expect(use.instruction == "add eax, ebx")

    def test_use_repr(self):
        """Test use string representation."""
        reg = Register("rdx", 64)
        use = Use(address=0x3000, register=reg)

        expect(not ("0x3000" not in repr(use)))
        expect(not ("rdx" not in repr(use)))


class TestDefUseChain:
    """Tests for DefUseChain class."""

    def test_chain_creation(self):
        """Test def-use chain creation."""
        reg = Register("eax", 32)
        defn = Definition(address=0x1000, register=reg)
        use1 = Use(address=0x1010, register=reg)
        use2 = Use(address=0x1020, register=reg)

        chain = DefUseChain(definition=defn, uses=[use1, use2], register=reg)

        expect(chain.definition == defn)
        expect(len(chain.uses) == _EXPECTED_LEN_CHAIN_USES_2)
        expect(chain.register == reg)

    def test_chain_add_use(self):
        """Test adding uses to chain."""
        reg = Register("ebx", 32)
        defn = Definition(address=0x1000, register=reg)
        chain = DefUseChain(definition=defn, register=reg)

        use = Use(address=0x1010, register=reg)
        chain.add_use(use)

        expect(len(chain.uses) == 1)
        expect(chain.uses[0] == use)

    def test_chain_live_range(self):
        """Test live range calculation."""
        reg = Register("ecx", 32)
        defn = Definition(address=0x1000, register=reg)
        use1 = Use(address=0x1010, register=reg)
        use2 = Use(address=0x1050, register=reg)

        chain = DefUseChain(definition=defn, uses=[use1, use2], register=reg)

        expect(chain.live_range == (4096, 4176))

    def test_chain_is_live_at(self):
        """Test is_live_at check."""
        reg = Register("edx", 32)
        defn = Definition(address=0x1000, register=reg)
        use = Use(address=0x1020, register=reg)

        chain = DefUseChain(definition=defn, uses=[use], register=reg)

        expect(not (chain.is_live_at(0x1000) is not True))
        expect(not (chain.is_live_at(0x1010) is not True))
        expect(not (chain.is_live_at(0x1020) is not True))
        expect(not (chain.is_live_at(0x1030) is not False))


class TestDataFlowResult:
    """Tests for DataFlowResult class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = DataFlowResult()

        expect(result.live_in == {})
        expect(result.live_out == {})
        expect(result.reaching_in == {})
        expect(result.reaching_out == {})
        expect(result.def_use_chains == [])

    def test_result_get_live_registers(self):
        """Test get_live_registers method."""
        result = DataFlowResult()
        reg1 = Register("eax", 32)
        reg2 = Register("ebx", 32)

        result.live_in[0x1000] = {reg1, reg2}
        result.live_in[0x2000] = {reg1}

        live_at_1000 = result.get_live_registers(0x1000)
        expect(len(live_at_1000) == _EXPECTED_LEN_LIVE_AT_1000_2)

        live_at_2000 = result.get_live_registers(0x2000)
        expect(len(live_at_2000) == 1)

        live_at_3000 = result.get_live_registers(0x3000)
        expect(len(live_at_3000) == 0)

    def test_result_is_register_live(self):
        """Test is_register_live method."""
        result = DataFlowResult()
        reg = Register("eax", 32)

        result.live_in[0x1000] = {reg}

        expect(not (result.is_register_live(0x1000, reg) is not True))
        expect(not (result.is_register_live(0x1000, Register("ebx", 32)) is not False))

    def test_result_get_reaching_definitions(self):
        """Test get_reaching_definitions method."""
        result = DataFlowResult()
        reg = Register("eax", 32)
        defn = Definition(address=0x1000, register=reg)

        result.reaching_in[0x1010] = {defn}

        reaching = result.get_reaching_definitions(0x1010)
        expect(len(reaching) == 1)
        expect(not (defn not in reaching))

        reaching_empty = result.get_reaching_definitions(0x2000)
        expect(len(reaching_empty) == 0)


class TestDataFlowAnalyzer:
    """Tests for DataFlowAnalyzer class."""

    def test_analyzer_creation(self):
        """Test analyzer initialization."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)

        expect(not (analyzer.cfg is not cfg))
        expect(isinstance(analyzer._result, DataFlowResult))

    def test_analyze_basic(self):
        """Test basic analysis."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        result = analyzer.analyze()

        expect(isinstance(result, DataFlowResult))
        expect(not (len(result.live_in) <= 0))
        expect(not (len(result.live_out) <= 0))

    def test_analyze_liveness(self):
        """Test liveness computation."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        analyzer._compute_liveness()

        expect(len(analyzer._result.live_in) == _EXPECTED_LEN_ANALYZER_RESULT_LIVE_IN_3)
        expect(len(analyzer._result.live_out) == _EXPECTED_LEN_ANALYZER_RESULT_LIVE_OUT_3)

    def test_analyze_reaching_definitions(self):
        """Test reaching definitions computation."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        analyzer._compute_reaching_definitions()

        expect(len(analyzer._result.reaching_in) == _EXPECTED_LEN_ANALYZER_RESULT_REACHING_IN_3)
        expect(len(analyzer._result.reaching_out) == _EXPECTED_LEN_ANALYZER_RESULT_REACHING_OUT_3)

    def test_get_block_use(self):
        """Test extracting registers used in block."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)

        block = cfg.blocks[0x1010]
        used = analyzer._get_block_use(block)

        expect(not (len(used) <= 0))
        reg_names = {r.name for r in used}
        expect("eax" in reg_names or "ebx" in reg_names)

    def test_get_block_def(self):
        """Test extracting registers defined in block."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)

        block = cfg.blocks[0x1000]
        defined = analyzer._get_block_def(block)

        expect(not (len(defined) <= 0))
        reg_names = {r.name for r in defined}
        expect("eax" in reg_names or "ebx" in reg_names)

    def test_extract_registers_from_operand(self):
        """Test register extraction from operands."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)

        regs = analyzer._extract_registers_from_operand("mov eax, ebx")
        reg_names = {r.name for r in regs}
        expect(not ("eax" not in reg_names))
        expect(not ("ebx" not in reg_names))

        regs = analyzer._extract_registers_from_operand("add rax, r8")
        reg_names = {r.name for r in regs}
        expect(not ("rax" not in reg_names))
        expect(not ("r8" not in reg_names))

    def test_indirect_call_uses_abi_registers(self):
        """Test indirect calls include implicit SysV argument registers."""
        analyzer = DataFlowAnalyzer(create_test_cfg())

        used = analyzer._extract_used_registers({"type": "icall", "disasm": "call rax"})
        reg_names = {register.name for register in used}

        expect({"rax", "rdi", "xmm0"}.issubset(reg_names))

    def test_indirect_call_defines_caller_saved_registers(self):
        """Test indirect calls include implicit caller-saved definitions."""
        analyzer = DataFlowAnalyzer(create_test_cfg())

        defined = analyzer._extract_defined_registers({"type": "icall", "disasm": "call rax"})
        reg_names = {register.name for register in defined}

        expect({"rax", "r11", "xmm15"}.issubset(reg_names))

    def test_is_safe_to_mutate(self):
        """Test mutation safety check."""
        cfg = create_test_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        analyzer.analyze()

        is_safe, reason = analyzer.is_safe_to_mutate(0x1010, "register_substitution")
        expect(isinstance(is_safe, bool))
        expect(isinstance(reason, str))

    def test_branching_cfg(self):
        """Test analysis on branching CFG."""
        cfg = create_branching_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        result = analyzer.analyze()

        expect(len(result.live_in) == _EXPECTED_LEN_RESULT_LIVE_IN_4)
        expect(len(result.live_out) == _EXPECTED_LEN_RESULT_LIVE_OUT_4)

    def test_loop_cfg(self):
        """Test analysis on loop CFG."""
        cfg = create_loop_cfg()
        analyzer = DataFlowAnalyzer(cfg)
        result = analyzer.analyze()

        expect(len(result.live_in) == _EXPECTED_LEN_RESULT_LIVE_IN_5)
        expect(len(result.live_out) == _EXPECTED_LEN_RESULT_LIVE_OUT_5)


class TestDataFlowDirection:
    """Tests for DataFlowDirection enum."""

    def test_direction_values(self):
        """Test direction enum values."""
        expect(DataFlowDirection.FORWARD.value == "forward")
        expect(DataFlowDirection.BACKWARD.value == "backward")
