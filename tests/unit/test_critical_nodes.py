"""
Unit tests for critical node detection module.
"""

import pytest
from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph, BlockType
from r2morph.analysis.critical_nodes import (
    AddressRange,
    CriticalNode,
    CriticalNodeDetector,
    MutationSafetyScorer,
    create_exclusion_zones,
    get_safe_mutation_addresses,
)


def create_simple_cfg() -> ControlFlowGraph:
    """Create a simple CFG for testing."""
    cfg = ControlFlowGraph(function_address=0x1000, function_name="simple")

    entry = BasicBlock(
        address=0x1000,
        size=16,
        instructions=[
            {"offset": 0x1000, "type": "mov", "disasm": "mov eax, 1"},
            {"offset": 0x1005, "type": "mov", "disasm": "mov ebx, 2"},
            {"offset": 0x100A, "type": "cmp", "disasm": "cmp eax, 0"},
        ],
        successors=[0x1010],
        predecessors=[],
        block_type=BlockType.ENTRY,
    )

    block2 = BasicBlock(
        address=0x1010,
        size=8,
        instructions=[
            {"offset": 0x1010, "type": "call", "disasm": "call func"},
            {"offset": 0x1015, "type": "add", "disasm": "add eax, ebx"},
        ],
        successors=[0x1020],
        predecessors=[0x1000],
        block_type=BlockType.CALL,
    )

    exit_block = BasicBlock(
        address=0x1020,
        size=4,
        instructions=[
            {"offset": 0x1020, "type": "ret", "disasm": "ret"},
        ],
        successors=[],
        predecessors=[0x1010],
        block_type=BlockType.RETURN,
    )

    cfg.add_block(entry)
    cfg.add_block(block2)
    cfg.add_block(exit_block)

    cfg.add_edge(0x1000, 0x1010)
    cfg.add_edge(0x1010, 0x1020)

    return cfg


def create_branching_cfg() -> ControlFlowGraph:
    """Create a CFG with branching."""
    cfg = ControlFlowGraph(function_address=0x2000, function_name="branch")

    entry = BasicBlock(
        address=0x2000,
        size=8,
        instructions=[
            {"offset": 0x2000, "type": "mov", "disasm": "mov eax, [rbp+8]"},
            {"offset": 0x2005, "type": "test", "disasm": "test eax, eax"},
        ],
        successors=[0x2010, 0x2020],
        predecessors=[],
        block_type=BlockType.CONDITIONAL,
    )

    then_block = BasicBlock(
        address=0x2010,
        size=4,
        instructions=[
            {"offset": 0x2010, "type": "mov", "disasm": "mov ebx, 1"},
        ],
        successors=[0x2030],
        predecessors=[0x2000],
        block_type=BlockType.NORMAL,
    )

    else_block = BasicBlock(
        address=0x2020,
        size=4,
        instructions=[
            {"offset": 0x2020, "type": "mov", "disasm": "mov ebx, 0"},
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
    cfg.add_block(then_block)
    cfg.add_block(else_block)
    cfg.add_block(merge)

    cfg.add_edge(0x2000, 0x2010)
    cfg.add_edge(0x2000, 0x2020)
    cfg.add_edge(0x2010, 0x2030)
    cfg.add_edge(0x2020, 0x2030)

    return cfg


def create_loop_cfg() -> ControlFlowGraph:
    """Create a CFG with a loop."""
    cfg = ControlFlowGraph(function_address=0x3000, function_name="loop")

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
        size=12,
        instructions=[
            {"offset": 0x3010, "type": "test", "disasm": "test ecx, ecx"},
            {"offset": 0x3015, "type": "jz", "disasm": "jz 0x3040"},
        ],
        successors=[0x3020, 0x3040],
        predecessors=[0x3000, 0x3030],
        block_type=BlockType.CONDITIONAL,
    )

    loop_body = BasicBlock(
        address=0x3020,
        size=12,
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


class TestAddressRange:
    """Tests for AddressRange class."""

    def test_range_creation(self):
        """Test address range creation."""
        r = AddressRange(start=0x1000, end=0x1020)

        assert r.start == 0x1000
        assert r.end == 0x1020

    def test_range_contains(self):
        """Test contains method."""
        r = AddressRange(start=0x1000, end=0x1020)

        assert 0x1000 in r
        assert 0x1010 in r
        assert 0x1020 in r
        assert 0x0999 not in r
        assert 0x1021 not in r

    def test_range_overlaps(self):
        """Test overlaps method."""
        r1 = AddressRange(start=0x1000, end=0x1020)
        r2 = AddressRange(start=0x1010, end=0x1030)
        r3 = AddressRange(start=0x1030, end=0x1050)

        assert r1.overlaps(r2) is True
        assert r2.overlaps(r1) is True
        assert r1.overlaps(r3) is False

    def test_range_merge(self):
        """Test merge method."""
        r1 = AddressRange(start=0x1000, end=0x1020)
        r2 = AddressRange(start=0x1010, end=0x1030)

        merged = r1.merge(r2)

        assert merged.start == 0x1000
        assert merged.end == 0x1030

    def test_range_size(self):
        """Test size method."""
        r = AddressRange(start=0x1000, end=0x1020)

        assert r.size() == 0x21

    def test_range_to_dict(self):
        """Test to_dict method."""
        r = AddressRange(start=0x1000, end=0x1020)
        d = r.to_dict()

        assert "start" in d
        assert "end" in d
        assert "size" in d


class TestCriticalNode:
    """Tests for CriticalNode class."""

    def test_node_creation(self):
        """Test critical node creation."""
        node = CriticalNode(
            address=0x1000,
            node_type="branch_target",
            reason="Target of branch instruction",
            exclusion_radius=3,
        )

        assert node.address == 0x1000
        assert node.node_type == "branch_target"
        assert node.exclusion_radius == 3

    def test_node_to_dict(self):
        """Test to_dict method."""
        node = CriticalNode(
            address=0x1000,
            node_type="call_site",
            reason="Call instruction",
        )
        d = node.to_dict()

        assert "address" in d
        assert "type" in d
        assert "reason" in d


class TestCriticalNodeDetector:
    """Tests for CriticalNodeDetector class."""

    def test_detector_creation(self):
        """Test detector creation."""
        cfg = create_simple_cfg()
        detector = CriticalNodeDetector(cfg)

        assert detector.cfg is cfg
        assert detector.default_exclusion_radius == 3

    def test_find_branch_targets(self):
        """Test finding branch targets."""
        cfg = create_branching_cfg()
        detector = CriticalNodeDetector(cfg)

        targets = detector.find_branch_targets()

        assert 0x2010 in targets
        assert 0x2020 in targets
        assert 0x2030 in targets

    def test_find_call_sites(self):
        """Test finding call sites."""
        cfg = create_simple_cfg()
        detector = CriticalNodeDetector(cfg)

        call_sites = detector.find_call_sites()

        assert 0x1010 in call_sites

    def test_find_entry_exits(self):
        """Test finding entry and exit points."""
        cfg = create_simple_cfg()
        detector = CriticalNodeDetector(cfg)

        entry_exits = detector.find_entry_exits()

        assert 0x1000 in entry_exits
        assert 0x1020 in entry_exits

    def test_find_loop_headers(self):
        """Test finding loop headers."""
        cfg = create_loop_cfg()
        detector = CriticalNodeDetector(cfg)

        loop_headers = detector.find_loop_headers()

        assert 0x3010 in loop_headers

    def test_find_all_critical_nodes(self):
        """Test finding all critical nodes."""
        cfg = create_branching_cfg()
        detector = CriticalNodeDetector(cfg)

        critical = detector.find_all_critical_nodes()

        assert len(critical) > 0
        assert all(isinstance(node, CriticalNode) for node in critical.values())

    def test_get_exclusion_zones(self):
        """Test getting exclusion zones."""
        cfg = create_branching_cfg()
        detector = CriticalNodeDetector(cfg, default_exclusion_radius=2)

        detector.find_all_critical_nodes()
        zones = detector.get_exclusion_zones()

        assert isinstance(zones, list)
        assert all(isinstance(z, AddressRange) for z in zones)

    def test_get_safe_regions(self):
        """Test getting safe regions."""
        cfg = create_branching_cfg()
        detector = CriticalNodeDetector(cfg)

        detector.find_all_critical_nodes()
        safe = detector.get_safe_regions()

        assert isinstance(safe, list)
        assert all(isinstance(r, AddressRange) for r in safe)

    def test_is_critical(self):
        """Test is_critical method."""
        cfg = create_simple_cfg()
        detector = CriticalNodeDetector(cfg)

        detector.find_all_critical_nodes()

        assert detector.is_critical(0x1000)
        assert detector.is_critical(0x1020)

    def test_is_in_exclusion_zone(self):
        """Test is_in_exclusion_zone method."""
        cfg = create_branching_cfg()
        detector = CriticalNodeDetector(cfg, default_exclusion_radius=5)

        detector.find_all_critical_nodes()
        zones = detector.get_exclusion_zones()

        for zone in zones:
            assert detector.is_in_exclusion_zone(zone.start)
            assert detector.is_in_exclusion_zone(zone.end)

    def test_get_critical_type(self):
        """Test get_critical_type method."""
        cfg = create_simple_cfg()
        detector = CriticalNodeDetector(cfg)

        detector.find_all_critical_nodes()

        assert detector.get_critical_type(0x1000) == "entry_exit"
        assert detector.get_critical_type(0x1020) == "entry_exit"

    def test_loop_cfg_detection(self):
        """Test detection with loop CFG."""
        cfg = create_loop_cfg()
        detector = CriticalNodeDetector(cfg)

        critical = detector.find_all_critical_nodes()

        assert 0x3010 in critical
        assert critical[0x3010].node_type == "loop_header"


class TestMutationSafetyScorer:
    """Tests for MutationSafetyScorer class."""

    def test_scorer_creation(self):
        """Test scorer creation."""
        scorer = MutationSafetyScorer()

        assert scorer._detector is None

    def test_score_address(self):
        """Test score_address method."""
        cfg = create_branching_cfg()
        scorer = MutationSafetyScorer()

        score = scorer.score_address(0x1000, cfg)
        assert 0.0 <= score <= 1.0

    def test_score_critical_address(self):
        """Test scoring a critical address."""
        cfg = create_simple_cfg()
        detector = CriticalNodeDetector(cfg)
        critical_nodes = detector.find_all_critical_nodes()
        scorer = MutationSafetyScorer()

        for addr in critical_nodes:
            score = scorer.score_address(addr, cfg, critical_nodes)
            assert score == 0.0

    def test_get_safest_addresses(self):
        """Test get_safest_addresses method."""
        cfg = create_branching_cfg()
        scorer = MutationSafetyScorer()

        safest = scorer.get_safest_addresses(cfg, count=3)

        assert len(safest) <= 3
        assert all(isinstance(addr, int) for addr, _ in safest)
        assert all(0.0 <= score <= 1.0 for _, score in safest)

        scores = [score for _, score in safest]
        assert scores == sorted(scores, reverse=True)

    def test_get_all_scores(self):
        """Test get_all_scores method."""
        cfg = create_branching_cfg()
        scorer = MutationSafetyScorer()

        scores = scorer.get_all_scores(cfg)

        assert isinstance(scores, dict)
        assert all(0.0 <= score <= 1.0 for score in scores.values())


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_exclusion_zones(self):
        """Test create_exclusion_zones function."""
        cfg = create_branching_cfg()

        zones = create_exclusion_zones(cfg, radius=3)

        assert isinstance(zones, list)
        assert all(isinstance(z, AddressRange) for z in zones)

    def test_get_safe_mutation_addresses(self):
        """Test get_safe_mutation_addresses function."""
        cfg = create_branching_cfg()

        safe = get_safe_mutation_addresses(cfg, count=5)

        assert isinstance(safe, list)
        assert len(safe) <= 5
        assert all(isinstance(addr, int) for addr in safe)


class TestComplexScenarios:
    """Tests for complex scenarios."""

    def test_multiple_critical_nodes(self):
        """Test detection with multiple critical node types."""
        cfg = create_loop_cfg()
        detector = CriticalNodeDetector(cfg)

        critical = detector.find_all_critical_nodes()

        types_found = set(node.node_type for node in critical.values())
        assert len(types_found) >= 1

    def test_exclusion_zone_merging(self):
        """Test that overlapping exclusion zones are merged."""
        cfg = create_branching_cfg()
        detector = CriticalNodeDetector(cfg, default_exclusion_radius=10)

        detector.find_all_critical_nodes()
        zones = detector.get_exclusion_zones()

        for i in range(len(zones) - 1):
            assert not zones[i].overlaps(zones[i + 1]) or zones[i].end < zones[i + 1].start

    def test_safe_region_boundaries(self):
        """Test that safe regions don't overlap with exclusion zones."""
        cfg = create_branching_cfg()
        detector = CriticalNodeDetector(cfg)

        detector.find_all_critical_nodes()
        exclusion = detector.get_exclusion_zones()
        safe = detector.get_safe_regions()

        for safe_region in safe:
            for exclusion_zone in exclusion:
                assert not safe_region.overlaps(
                    exclusion_zone
                ), f"Safe region 0x{safe_region.start:x}-0x{safe_region.end:x} overlaps with exclusion zone 0x{exclusion_zone.start:x}-0x{exclusion_zone.end:x}"

    def test_nearby_critical_nodes(self):
        """Test get_nearby_critical_nodes method."""
        cfg = create_branching_cfg()
        detector = CriticalNodeDetector(cfg)

        detector.find_all_critical_nodes()

        nearby = detector.get_nearby_critical_nodes(0x2000, radius=32)

        assert isinstance(nearby, list)
        assert all(isinstance(node, CriticalNode) for node in nearby)
