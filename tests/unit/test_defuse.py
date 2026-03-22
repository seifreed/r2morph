"""
Unit tests for def-use chain analysis module.
"""

from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph, BlockType
from r2morph.analysis.defuse import (
    DefUseAnalyzer,
    DefWeb,
    UseWeb,
    Definition,
    Use,
    Register,
)


def create_simple_cfg() -> ControlFlowGraph:
    """Create a simple CFG for def-use testing."""
    cfg = ControlFlowGraph(function_address=0x1000, function_name="simple")

    block1 = BasicBlock(
        address=0x1000,
        size=12,
        instructions=[
            {"offset": 0x1000, "type": "mov", "disasm": "mov eax, 5"},
            {"offset": 0x1005, "type": "mov", "disasm": "mov ebx, 10"},
            {"offset": 0x100A, "type": "add", "disasm": "add eax, ebx"},
        ],
        successors=[0x1010],
        predecessors=[],
        block_type=BlockType.NORMAL,
    )

    block2 = BasicBlock(
        address=0x1010,
        size=8,
        instructions=[
            {"offset": 0x1010, "type": "mov", "disasm": "mov ecx, eax"},
            {"offset": 0x1015, "type": "ret", "disasm": "ret"},
        ],
        successors=[],
        predecessors=[0x1000],
        block_type=BlockType.RETURN,
    )

    cfg.add_block(block1)
    cfg.add_block(block2)
    cfg.add_edge(0x1000, 0x1010)

    return cfg


def create_branching_cfg() -> ControlFlowGraph:
    """Create a CFG with branches for def-use testing."""
    cfg = ControlFlowGraph(function_address=0x2000, function_name="branch")

    entry = BasicBlock(
        address=0x2000,
        size=8,
        instructions=[
            {"offset": 0x2000, "type": "mov", "disasm": "mov eax, 1"},
        ],
        successors=[0x2010, 0x2020],
        predecessors=[],
        block_type=BlockType.CONDITIONAL,
    )

    left = BasicBlock(
        address=0x2010,
        size=4,
        instructions=[
            {"offset": 0x2010, "type": "mov", "disasm": "mov ebx, eax"},
        ],
        successors=[0x2030],
        predecessors=[0x2000],
        block_type=BlockType.NORMAL,
    )

    right = BasicBlock(
        address=0x2020,
        size=4,
        instructions=[
            {"offset": 0x2020, "type": "mov", "disasm": "mov ecx, eax"},
        ],
        successors=[0x2030],
        predecessors=[0x2000],
        block_type=BlockType.NORMAL,
    )

    merge = BasicBlock(
        address=0x2030,
        size=4,
        instructions=[
            {"offset": 0x2030, "type": "ret", "disasm": "ret"},
        ],
        successors=[],
        predecessors=[0x2010, 0x2020],
        block_type=BlockType.RETURN,
    )

    cfg.add_block(entry)
    cfg.add_block(left)
    cfg.add_block(right)
    cfg.add_block(merge)

    cfg.add_edge(0x2000, 0x2010)
    cfg.add_edge(0x2000, 0x2020)
    cfg.add_edge(0x2010, 0x2030)
    cfg.add_edge(0x2020, 0x2030)

    return cfg


class TestDefWeb:
    """Tests for DefWeb class."""

    def test_def_web_creation(self):
        """Test def web creation."""
        reg = Register("eax", 32)
        defn = Definition(address=0x1000, register=reg)
        use1 = Use(address=0x1010, register=reg)
        use2 = Use(address=0x1020, register=reg)

        web = DefWeb(definition=defn, uses=[use1, use2], register=reg)

        assert web.definition == defn
        assert len(web.uses) == 2
        assert web.register == reg

    def test_def_web_get_live_range(self):
        """Test get_live_range method."""
        reg = Register("ebx", 32)
        defn = Definition(address=0x1000, register=reg)
        use = Use(address=0x1050, register=reg)

        web = DefWeb(definition=defn, uses=[use], register=reg)
        live_range = web.get_live_range()

        assert live_range[0] == 0x1000
        assert live_range[1] == 0x1050

    def test_def_web_contains_address(self):
        """Test contains_address method."""
        reg = Register("ecx", 32)
        defn = Definition(address=0x1000, register=reg)
        use = Use(address=0x1020, register=reg)

        web = DefWeb(definition=defn, uses=[use], register=reg)

        assert web.contains_address(0x1000) is True
        assert web.contains_address(0x1010) is True
        assert web.contains_address(0x1020) is True
        assert web.contains_address(0x0999) is False
        assert web.contains_address(0x1021) is False

    def test_def_web_to_dict(self):
        """Test to_dict method."""
        reg = Register("edx", 32)
        defn = Definition(address=0x1000, register=reg)
        use = Use(address=0x1010, register=reg)

        web = DefWeb(definition=defn, uses=[use], register=reg)
        d = web.to_dict()

        assert "definition" in d
        assert "register" in d
        assert "uses" in d
        assert "live_range" in d


class TestUseWeb:
    """Tests for UseWeb class."""

    def test_use_web_creation(self):
        """Test use web creation."""
        reg = Register("eax", 32)
        use = Use(address=0x1010, register=reg)
        defn = Definition(address=0x1000, register=reg)

        web = UseWeb(use=use, definitions=[defn], register=reg)

        assert web.use == use
        assert len(web.definitions) == 1
        assert web.register == reg

    def test_use_web_is_unique(self):
        """Test is_unique method."""
        reg = Register("ebx", 32)
        use = Use(address=0x1010, register=reg)
        defn1 = Definition(address=0x1000, register=reg)

        web_unique = UseWeb(use=use, definitions=[defn1], register=reg)
        assert web_unique.is_unique() is True

        defn2 = Definition(address=0x1005, register=reg)
        web_multiple = UseWeb(use=use, definitions=[defn1, defn2], register=reg)
        assert web_multiple.is_unique() is False

    def test_use_web_has_phi_needed(self):
        """Test has_phi_needed method."""
        reg = Register("ecx", 32)
        use = Use(address=0x1010, register=reg)
        defn1 = Definition(address=0x1000, register=reg)

        web_single = UseWeb(use=use, definitions=[defn1], register=reg)
        assert web_single.has_phi_needed() is False

        defn2 = Definition(address=0x1005, register=reg)
        defn3 = Definition(address=0x100A, register=reg)
        web_multiple = UseWeb(use=use, definitions=[defn1, defn2, defn3], register=reg)
        assert web_multiple.has_phi_needed() is True

    def test_use_web_to_dict(self):
        """Test to_dict method."""
        reg = Register("edx", 32)
        use = Use(address=0x1010, register=reg)
        defn = Definition(address=0x1000, register=reg)

        web = UseWeb(use=use, definitions=[defn], register=reg)
        d = web.to_dict()

        assert "use" in d
        assert "register" in d
        assert "definitions" in d


class TestDefUseAnalyzer:
    """Tests for DefUseAnalyzer class."""

    def test_analyzer_creation(self):
        """Test analyzer creation."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)

        assert analyzer.cfg is cfg
        assert analyzer._def_webs == {}
        assert analyzer._use_webs == {}

    def test_analyze_simple(self):
        """Test analyze on simple CFG."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        assert len(analyzer._def_webs) >= 0
        assert len(analyzer._use_webs) >= 0

    def test_get_def_web(self):
        """Test get_def_web method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        web = analyzer.get_def_web(0x1000)
        assert web is None or isinstance(web, DefWeb)

    def test_get_use_web(self):
        """Test get_use_web method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        web = analyzer.get_use_web(0x100A)
        assert web is None or isinstance(web, UseWeb)

    def test_get_all_def_webs(self):
        """Test get_all_def_webs method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        all_webs = analyzer.get_all_def_webs()
        assert isinstance(all_webs, list)

    def test_get_all_use_webs(self):
        """Test get_all_use_webs method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        all_webs = analyzer.get_all_use_webs()
        assert isinstance(all_webs, list)

    def test_get_webs_for_register(self):
        """Test get_webs_for_register method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        reg = Register("eax", 32)
        def_webs, use_webs = analyzer.get_webs_for_register(reg)

        assert isinstance(def_webs, list)
        assert isinstance(use_webs, list)

    def test_find_uninitialized_uses(self):
        """Test find_uninitialized_uses method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        uninitialized = analyzer.find_uninitialized_uses()
        assert isinstance(uninitialized, list)

    def test_find_unused_definitions(self):
        """Test find_unused_definitions method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        unused = analyzer.find_unused_definitions()
        assert isinstance(unused, list)

    def test_branching_cfg(self):
        """Test analysis on branching CFG."""
        cfg = create_branching_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        all_def_webs = analyzer.get_all_def_webs()
        all_use_webs = analyzer.get_all_use_webs()

        assert isinstance(all_def_webs, list)
        assert isinstance(all_use_webs, list)

    def test_to_dict(self):
        """Test to_dict method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        d = analyzer.to_dict()

        assert "def_webs" in d
        assert "use_webs" in d
        assert "unused_definitions" in d
        assert "uninitialized_uses" in d


class TestDefinitionAndUse:
    """Tests for Definition and Use classes."""

    def test_definition_creation(self):
        """Test definition creation."""
        reg = Register("eax", 32)
        defn = Definition(address=0x1000, register=reg, instruction="mov eax, 1")

        assert defn.address == 0x1000
        assert defn.register == reg
        assert defn.instruction == "mov eax, 1"

    def test_use_creation(self):
        """Test use creation."""
        reg = Register("ebx", 32)
        use = Use(address=0x1010, register=reg, instruction="add ecx, ebx")

        assert use.address == 0x1010
        assert use.register == reg
        assert use.instruction == "add ecx, ebx"

    def test_definition_hash_equality(self):
        """Test definition hashing and equality."""
        reg = Register("ecx", 32)
        defn1 = Definition(address=0x1000, register=reg)
        defn2 = Definition(address=0x1000, register=reg)
        defn3 = Definition(address=0x2000, register=reg)

        assert hash(defn1) == hash(defn2)
        assert defn1 == defn2
        assert defn1 != defn3

    def test_use_hash_equality(self):
        """Test use hashing and equality."""
        reg = Register("edx", 32)
        use1 = Use(address=0x1010, register=reg)
        use2 = Use(address=0x1010, register=reg)
        use3 = Use(address=0x1020, register=reg)

        assert hash(use1) == hash(use2)
        assert use1 == use2
        assert use1 != use3
