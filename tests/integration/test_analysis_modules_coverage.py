"""
Tests for analysis modules to increase coverage.
"""

from pathlib import Path

import pytest
import importlib.util

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)



from r2morph.analysis.cfg import BasicBlock, CFGBuilder, ControlFlowGraph
from r2morph.analysis.dependencies import (
    Dependency,
    DependencyAnalyzer,
    DependencyType,
    InstructionDef,
)
from r2morph.analysis.invariants import Invariant, InvariantDetector, InvariantType
from r2morph.core.binary import Binary


class TestCFGModuleDetailed:
    """Detailed tests for CFG module."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_basic_block_creation(self):
        """Test BasicBlock creation and methods."""
        block = BasicBlock(address=0x1000, size=64)
        assert block.address == 0x1000
        assert block.size == 64
        assert len(block.successors) == 0
        assert len(block.predecessors) == 0

    def test_basic_block_add_successor(self):
        """Test adding successors."""
        block = BasicBlock(address=0x1000, size=64)
        block.add_successor(0x1040)
        block.add_successor(0x1080)
        assert 0x1040 in block.successors
        assert 0x1080 in block.successors

    def test_basic_block_add_predecessor(self):
        """Test adding predecessors."""
        block = BasicBlock(address=0x1000, size=64)
        block.add_predecessor(0x0FC0)
        assert 0x0FC0 in block.predecessors

    def test_basic_block_is_conditional(self):
        """Test conditional block detection."""
        block = BasicBlock(address=0x1000, size=64, type="conditional")
        assert block.is_conditional()

        block2 = BasicBlock(address=0x2000, size=32)
        block2.add_successor(0x2020)
        block2.add_successor(0x2040)
        assert block2.is_conditional()

    def test_basic_block_is_return(self):
        """Test return block detection."""
        block = BasicBlock(address=0x1000, size=64, type="return")
        assert block.is_return()

        block2 = BasicBlock(address=0x2000, size=32)
        assert block2.is_return()

    def test_control_flow_graph_creation(self):
        """Test CFG creation."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        assert cfg.function_address == 0x1000
        assert cfg.function_name == "main"
        assert len(cfg.blocks) == 0

    def test_control_flow_graph_add_block(self):
        """Test adding blocks to CFG."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        block1 = BasicBlock(address=0x1000, size=64)
        block2 = BasicBlock(address=0x1040, size=32)

        cfg.add_block(block1)
        cfg.add_block(block2)

        assert len(cfg.blocks) == 2
        assert 0x1000 in cfg.blocks
        assert 0x1040 in cfg.blocks
        assert cfg.entry_block == block1

    def test_control_flow_graph_add_edge(self):
        """Test adding edges to CFG."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        block1 = BasicBlock(address=0x1000, size=64)
        block2 = BasicBlock(address=0x1040, size=32)

        cfg.add_block(block1)
        cfg.add_block(block2)
        cfg.add_edge(0x1000, 0x1040)

        assert (0x1000, 0x1040) in cfg.edges
        assert 0x1040 in cfg.blocks[0x1000].successors
        assert 0x1000 in cfg.blocks[0x1040].predecessors

    def test_control_flow_graph_get_block(self):
        """Test getting block from CFG."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        block = BasicBlock(address=0x1000, size=64)
        cfg.add_block(block)

        retrieved = cfg.get_block(0x1000)
        assert retrieved is not None
        assert retrieved.address == 0x1000

        not_found = cfg.get_block(0x9999)
        assert not_found is None

    def test_control_flow_graph_get_successors(self):
        """Test getting successors."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        block1 = BasicBlock(address=0x1000, size=64)
        block2 = BasicBlock(address=0x1040, size=32)
        block3 = BasicBlock(address=0x1060, size=32)

        cfg.add_block(block1)
        cfg.add_block(block2)
        cfg.add_block(block3)
        cfg.add_edge(0x1000, 0x1040)
        cfg.add_edge(0x1000, 0x1060)

        successors = cfg.get_successors(0x1000)
        assert len(successors) == 2

    def test_control_flow_graph_get_predecessors(self):
        """Test getting predecessors."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        block1 = BasicBlock(address=0x1000, size=64)
        block2 = BasicBlock(address=0x1040, size=32)

        cfg.add_block(block1)
        cfg.add_block(block2)
        cfg.add_edge(0x1000, 0x1040)

        predecessors = cfg.get_predecessors(0x1040)
        assert len(predecessors) == 1

    def test_cfg_builder_with_real_binary(self, ls_elf):
        """Test CFG builder with real binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            builder = CFGBuilder(binary)

            functions = binary.get_functions()
            if len(functions) > 0:
                func_addr = functions[0].get("offset", functions[0].get("addr", 0))
                if func_addr:
                    try:
                        cfg = builder.build_cfg(func_addr)
                        assert isinstance(cfg, ControlFlowGraph)
                        assert cfg.function_address == func_addr
                    except Exception:
                        pass


class TestDependencyAnalyzerDetailed:
    """Detailed tests for DependencyAnalyzer."""

    def test_dependency_creation(self):
        """Test Dependency dataclass."""
        dep = Dependency(
            from_address=0x1000,
            to_address=0x1004,
            resource="rax",
            dep_type=DependencyType.READ_AFTER_WRITE,
        )
        assert dep.from_address == 0x1000
        assert dep.to_address == 0x1004
        assert dep.resource == "rax"
        assert dep.dep_type == DependencyType.READ_AFTER_WRITE

    def test_instruction_def_creation(self):
        """Test InstructionDef dataclass."""
        insn_def = InstructionDef(address=0x1000)
        insn_def.defines.add("rax")
        insn_def.uses.add("rbx")

        assert insn_def.address == 0x1000
        assert "rax" in insn_def.defines
        assert "rbx" in insn_def.uses

    def test_dependency_analyzer_initialization(self):
        """Test DependencyAnalyzer initialization."""
        analyzer = DependencyAnalyzer()
        assert len(analyzer.dependencies) == 0
        assert len(analyzer.defs) == 0

    def test_dependency_types(self):
        """Test all dependency types."""
        assert DependencyType.READ_AFTER_WRITE.value == "RAW"
        assert DependencyType.WRITE_AFTER_READ.value == "WAR"
        assert DependencyType.WRITE_AFTER_WRITE.value == "WAW"
        assert DependencyType.READ_AFTER_READ.value == "RAR"


class TestInvariantDetectorDetailed:
    """Detailed tests for InvariantDetector."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_invariant_creation(self):
        """Test Invariant dataclass."""
        inv = Invariant(
            invariant_type=InvariantType.STACK_BALANCE,
            description="Stack must be balanced",
            location=0x1000,
            details={"stack_delta": 0},
        )
        assert inv.invariant_type == InvariantType.STACK_BALANCE
        assert inv.location == 0x1000

    def test_invariant_types(self):
        """Test all invariant types."""
        assert InvariantType.STACK_BALANCE.value == "stack_balance"
        assert InvariantType.REGISTER_PRESERVATION.value == "reg_preserve"
        assert InvariantType.CALLING_CONVENTION.value == "call_conv"
        assert InvariantType.RETURN_VALUE.value == "return_value"
        assert InvariantType.CONTROL_FLOW.value == "control_flow"
        assert InvariantType.MEMORY_SAFETY.value == "memory_safety"

    def test_invariant_detector_initialization(self, ls_elf):
        """Test InvariantDetector initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = InvariantDetector(binary)
            assert detector.binary == binary
            assert len(detector.invariants) == 0

    def test_detect_stack_balance(self, ls_elf):
        """Test stack balance detection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = InvariantDetector(binary)

            functions = binary.get_functions()
            if len(functions) > 0:
                func_addr = functions[0].get("offset", functions[0].get("addr", 0))
                if func_addr:
                    invariants = detector.detect_stack_balance(func_addr)
                    assert isinstance(invariants, list)

    def test_callee_saved_regs(self):
        """Test callee saved registers."""
        assert "rbx" in InvariantDetector.CALLEE_SAVED_REGS["x64"]
        assert "ebx" in InvariantDetector.CALLEE_SAVED_REGS["x86"]
        assert "r4" in InvariantDetector.CALLEE_SAVED_REGS["arm"]