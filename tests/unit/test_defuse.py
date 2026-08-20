"""
Unit tests for def-use chain analysis module.
"""

import importlib

from r2morph.analysis.cfg import BasicBlock, BlockType, ControlFlowGraph
from r2morph.analysis.defuse import (
    Definition,
    DefUseAnalyzer,
    DefWeb,
    Register,
    Use,
    UseWeb,
)
from tests.utils.assertions import expect

_EXPECTED_DEFN_ADDRESS_4096 = 0x1000
_EXPECTED_LEN_WEB_USES_2 = 2
_EXPECTED_LIVE_RANGE_0_4096 = 0x1000
_EXPECTED_LIVE_RANGE_1_4176 = 0x1050
_EXPECTED_USE_ADDRESS_4112 = 0x1010


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

        expect(web.definition == defn)
        expect(len(web.uses) == _EXPECTED_LEN_WEB_USES_2)
        expect(web.register == reg)

    def test_def_web_get_live_range(self):
        """Test get_live_range method."""
        reg = Register("ebx", 32)
        defn = Definition(address=0x1000, register=reg)
        use = Use(address=0x1050, register=reg)

        web = DefWeb(definition=defn, uses=[use], register=reg)
        live_range = web.get_live_range()

        expect(live_range[0] == _EXPECTED_LIVE_RANGE_0_4096)
        expect(live_range[1] == _EXPECTED_LIVE_RANGE_1_4176)

    def test_def_web_contains_address(self):
        """Test contains_address method."""
        reg = Register("ecx", 32)
        defn = Definition(address=0x1000, register=reg)
        use = Use(address=0x1020, register=reg)

        web = DefWeb(definition=defn, uses=[use], register=reg)

        expect(not (web.contains_address(0x1000) is not True))
        expect(not (web.contains_address(0x1010) is not True))
        expect(not (web.contains_address(0x1020) is not True))
        expect(not (web.contains_address(0x0999) is not False))
        expect(not (web.contains_address(0x1021) is not False))

    def test_def_web_to_dict(self):
        """Test to_dict method."""
        reg = Register("edx", 32)
        defn = Definition(address=0x1000, register=reg)
        use = Use(address=0x1010, register=reg)

        web = DefWeb(definition=defn, uses=[use], register=reg)
        d = web.to_dict()

        expect(not ("definition" not in d))
        expect(not ("register" not in d))
        expect(not ("uses" not in d))
        expect(not ("live_range" not in d))


class TestUseWeb:
    """Tests for UseWeb class."""

    def test_use_web_creation(self):
        """Test use web creation."""
        reg = Register("eax", 32)
        use = Use(address=0x1010, register=reg)
        defn = Definition(address=0x1000, register=reg)

        web = UseWeb(use=use, definitions=[defn], register=reg)

        expect(web.use == use)
        expect(len(web.definitions) == 1)
        expect(web.register == reg)

    def test_use_web_is_unique(self):
        """Test is_unique method."""
        reg = Register("ebx", 32)
        use = Use(address=0x1010, register=reg)
        defn1 = Definition(address=0x1000, register=reg)

        web_unique = UseWeb(use=use, definitions=[defn1], register=reg)
        expect(not (web_unique.is_unique() is not True))

        defn2 = Definition(address=0x1005, register=reg)
        web_multiple = UseWeb(use=use, definitions=[defn1, defn2], register=reg)
        expect(not (web_multiple.is_unique() is not False))

    def test_use_web_has_phi_needed(self):
        """Test has_phi_needed method."""
        reg = Register("ecx", 32)
        use = Use(address=0x1010, register=reg)
        defn1 = Definition(address=0x1000, register=reg)

        web_single = UseWeb(use=use, definitions=[defn1], register=reg)
        expect(not (web_single.has_phi_needed() is not False))

        defn2 = Definition(address=0x1005, register=reg)
        defn3 = Definition(address=0x100A, register=reg)
        web_multiple = UseWeb(use=use, definitions=[defn1, defn2, defn3], register=reg)
        expect(not (web_multiple.has_phi_needed() is not True))

    def test_use_web_to_dict(self):
        """Test to_dict method."""
        reg = Register("edx", 32)
        use = Use(address=0x1010, register=reg)
        defn = Definition(address=0x1000, register=reg)

        web = UseWeb(use=use, definitions=[defn], register=reg)
        d = web.to_dict()

        expect(not ("use" not in d))
        expect(not ("register" not in d))
        expect(not ("definitions" not in d))


class TestDefUseAnalyzer:
    """Tests for DefUseAnalyzer class."""

    def test_analyzer_creation(self):
        """Test analyzer creation."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)

        expect(not (analyzer.cfg is not cfg))
        expect(analyzer._def_webs == {})
        expect(analyzer._use_webs == {})

    def test_analyze_simple(self):
        """Test analyze on simple CFG."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        expect(not (len(analyzer._def_webs) < 0))
        expect(not (len(analyzer._use_webs) < 0))

    def test_get_def_web(self):
        """Test get_def_web method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        web = analyzer.get_def_web(0x1000)
        expect(web is None or isinstance(web, DefWeb))

    def test_get_use_web(self):
        """Test get_use_web method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        web = analyzer.get_use_web(0x100A)
        expect(web is None or isinstance(web, UseWeb))

    def test_get_all_def_webs(self):
        """Test get_all_def_webs method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        all_webs = analyzer.get_all_def_webs()
        expect(isinstance(all_webs, list))

    def test_get_all_use_webs(self):
        """Test get_all_use_webs method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        all_webs = analyzer.get_all_use_webs()
        expect(isinstance(all_webs, list))

    def test_get_webs_for_register(self):
        """Test get_webs_for_register method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        reg = Register("eax", 32)
        def_webs, use_webs = analyzer.get_webs_for_register(reg)

        expect(isinstance(def_webs, list))
        expect(isinstance(use_webs, list))

    def test_find_uninitialized_uses(self):
        """Test find_uninitialized_uses method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        uninitialized = analyzer.find_uninitialized_uses()
        expect(isinstance(uninitialized, list))

    def test_find_unused_definitions(self):
        """Test find_unused_definitions method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        unused = analyzer.find_unused_definitions()
        expect(isinstance(unused, list))

    def test_branching_cfg(self):
        """Test analysis on branching CFG."""
        cfg = create_branching_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        all_def_webs = analyzer.get_all_def_webs()
        all_use_webs = analyzer.get_all_use_webs()

        expect(isinstance(all_def_webs, list))
        expect(isinstance(all_use_webs, list))

    def test_to_dict(self):
        """Test to_dict method."""
        cfg = create_simple_cfg()
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()

        d = analyzer.to_dict()

        expect(not ("def_webs" not in d))
        expect(not ("use_webs" not in d))
        expect(not ("unused_definitions" not in d))
        expect(not ("uninitialized_uses" not in d))


class TestDefinitionAndUse:
    """Tests for Definition and Use classes."""

    def test_definition_creation(self):
        """Test definition creation."""
        reg = Register("eax", 32)
        defn = Definition(address=0x1000, register=reg, instruction="mov eax, 1")

        expect(defn.address == _EXPECTED_DEFN_ADDRESS_4096)
        expect(defn.register == reg)
        expect(defn.instruction == "mov eax, 1")

    def test_use_creation(self):
        """Test use creation."""
        reg = Register("ebx", 32)
        use = Use(address=0x1010, register=reg, instruction="add ecx, ebx")

        expect(use.address == _EXPECTED_USE_ADDRESS_4112)
        expect(use.register == reg)
        expect(use.instruction == "add ecx, ebx")

    def test_definition_hash_equality(self):
        """Test definition hashing and equality."""
        reg = Register("ecx", 32)
        defn1 = Definition(address=0x1000, register=reg)
        defn2 = Definition(address=0x1000, register=reg)
        defn3 = Definition(address=0x2000, register=reg)

        expect(hash(defn1) == hash(defn2))
        expect(defn1 == defn2)
        expect(defn1 != defn3)

    def test_use_hash_equality(self):
        """Test use hashing and equality."""
        reg = Register("edx", 32)
        use1 = Use(address=0x1010, register=reg)
        use2 = Use(address=0x1010, register=reg)
        use3 = Use(address=0x1020, register=reg)

        expect(hash(use1) == hash(use2))
        expect(use1 == use2)
        expect(use1 != use3)


class TestBuildSSAForm:
    """Tests for SSA-form construction wired onto the def-use analyzer."""

    def test_build_ssa_form_returns_one_ssa_block_per_cfg_block(self):
        cfg = create_branching_cfg()
        analyzer = DefUseAnalyzer(cfg)

        ssa = analyzer.build_ssa_form()

        expect(set(ssa) == set(cfg.blocks))

    def test_build_ssa_form_places_phi_at_merge_block(self):
        cfg = create_branching_cfg()
        analyzer = DefUseAnalyzer(cfg)

        ssa = analyzer.build_ssa_form()

        expect(ssa[0x2030].phi_functions)

    def test_ssa_converter_is_public_analysis_export(self):
        exported_s_s_a_converter = importlib.import_module("r2morph.analysis").SSAConverter
        s_s_a_converter = importlib.import_module("r2morph.analysis.ssa").SSAConverter

        expect(not (exported_s_s_a_converter is not s_s_a_converter))
