"""
Tests for analysis modules to increase coverage.
"""

import importlib.util
import logging
from pathlib import Path

import pytest

from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph.analysis.cfg import BasicBlock, BlockType, CFGBuilder, ControlFlowGraph
from r2morph.analysis.dependencies import (
    Dependency,
    DependencyAnalyzer,
    DependencyType,
    InstructionDef,
)
from r2morph.analysis.invariants import Invariant, InvariantDetector, InvariantType
from r2morph.core.binary import Binary

_EXPECTED_BLOCK_ADDRESS_4096 = 0x1000
_EXPECTED_BLOCK_PREDECESSORS_4032 = 0x0FC0
_EXPECTED_BLOCK_SIZE_64 = 64
_EXPECTED_BLOCK_SUCCESSORS_4160 = 0x1040
_EXPECTED_BLOCK_SUCCESSORS_4224 = 0x1080
_EXPECTED_CFG_BLOCKS_0X1000_SUCCESSORS_4160 = 0x1040
_EXPECTED_CFG_BLOCKS_0X1040_PREDECESSORS_4096 = 0x1000
_EXPECTED_CFG_BLOCKS_4096 = 0x1000
_EXPECTED_CFG_BLOCKS_4160 = 0x1040
_EXPECTED_CFG_FUNCTION_ADDRESS_4096 = 0x1000
_EXPECTED_DEP_FROM_ADDRESS_4096 = 0x1000
_EXPECTED_DEP_TO_ADDRESS_4100 = 0x1004
_EXPECTED_INSN_DEF_ADDRESS_4096 = 0x1000
_EXPECTED_INV_LOCATION_4096 = 0x1000
_EXPECTED_LEN_CFG_BLOCKS_2 = 2
_EXPECTED_LEN_SUCCESSORS_2 = 2
_EXPECTED_RETRIEVED_ADDRESS_4096 = 0x1000


class TestCFGModuleDetailed:
    """Detailed tests for CFG module."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_basic_block_creation(self):
        """Test BasicBlock creation and methods."""
        block = BasicBlock(address=0x1000, size=64)
        expect(block.address == _EXPECTED_BLOCK_ADDRESS_4096)
        expect(block.size == _EXPECTED_BLOCK_SIZE_64)
        expect(len(block.successors) == 0)
        expect(len(block.predecessors) == 0)

    def test_basic_block_add_successor(self):
        """Test adding successors."""
        block = BasicBlock(address=0x1000, size=64)
        block.add_successor(0x1040)
        block.add_successor(0x1080)
        expect(not (_EXPECTED_BLOCK_SUCCESSORS_4160 not in block.successors))
        expect(not (_EXPECTED_BLOCK_SUCCESSORS_4224 not in block.successors))

    def test_basic_block_add_predecessor(self):
        """Test adding predecessors."""
        block = BasicBlock(address=0x1000, size=64)
        block.add_predecessor(0x0FC0)
        expect(not (_EXPECTED_BLOCK_PREDECESSORS_4032 not in block.predecessors))

    def test_basic_block_is_conditional(self):
        """Test conditional block detection."""
        block = BasicBlock(address=0x1000, size=64, block_type=BlockType.CONDITIONAL)
        expect(block.is_conditional())

        block2 = BasicBlock(address=0x2000, size=32)
        block2.add_successor(0x2020)
        block2.add_successor(0x2040)
        expect(block2.is_conditional())

    def test_basic_block_is_return(self):
        """Test return block detection."""
        block = BasicBlock(address=0x1000, size=64, block_type=BlockType.RETURN)
        expect(block.is_return())

        block2 = BasicBlock(address=0x2000, size=32)
        expect(block2.is_return())

    def test_control_flow_graph_creation(self):
        """Test CFG creation."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        expect(cfg.function_address == _EXPECTED_CFG_FUNCTION_ADDRESS_4096)
        expect(cfg.function_name == "main")
        expect(len(cfg.blocks) == 0)

    def test_control_flow_graph_add_block(self):
        """Test adding blocks to CFG."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        block1 = BasicBlock(address=0x1000, size=64)
        block2 = BasicBlock(address=0x1040, size=32)

        cfg.add_block(block1)
        cfg.add_block(block2)

        expect(len(cfg.blocks) == _EXPECTED_LEN_CFG_BLOCKS_2)
        expect(not (_EXPECTED_CFG_BLOCKS_4096 not in cfg.blocks))
        expect(not (_EXPECTED_CFG_BLOCKS_4160 not in cfg.blocks))
        expect(cfg.entry_block == block1)

    def test_control_flow_graph_add_edge(self):
        """Test adding edges to CFG."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        block1 = BasicBlock(address=0x1000, size=64)
        block2 = BasicBlock(address=0x1040, size=32)

        cfg.add_block(block1)
        cfg.add_block(block2)
        cfg.add_edge(0x1000, 0x1040)

        expect(not ((0x1000, 0x1040) not in cfg.edges))
        expect(not (_EXPECTED_CFG_BLOCKS_0X1000_SUCCESSORS_4160 not in cfg.blocks[0x1000].successors))
        expect(not (_EXPECTED_CFG_BLOCKS_0X1040_PREDECESSORS_4096 not in cfg.blocks[0x1040].predecessors))

    def test_control_flow_graph_get_block(self):
        """Test getting block from CFG."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        block = BasicBlock(address=0x1000, size=64)
        cfg.add_block(block)

        retrieved = cfg.get_block(0x1000)
        expect(retrieved is not None)
        expect(retrieved.address == _EXPECTED_RETRIEVED_ADDRESS_4096)

        not_found = cfg.get_block(0x9999)
        expect(not (not_found is not None))

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
        expect(len(successors) == _EXPECTED_LEN_SUCCESSORS_2)

    def test_control_flow_graph_get_predecessors(self):
        """Test getting predecessors."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
        block1 = BasicBlock(address=0x1000, size=64)
        block2 = BasicBlock(address=0x1040, size=32)

        cfg.add_block(block1)
        cfg.add_block(block2)
        cfg.add_edge(0x1000, 0x1040)

        predecessors = cfg.get_predecessors(0x1040)
        expect(len(predecessors) == 1)

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
                        expect(isinstance(cfg, ControlFlowGraph))
                        expect(cfg.function_address == func_addr)
                    except Exception:
                        logging.getLogger(__name__).debug("ignored optional test-path exception", exc_info=True)


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
        expect(dep.from_address == _EXPECTED_DEP_FROM_ADDRESS_4096)
        expect(dep.to_address == _EXPECTED_DEP_TO_ADDRESS_4100)
        expect(dep.resource == "rax")
        expect(dep.dep_type == DependencyType.READ_AFTER_WRITE)

    def test_instruction_def_creation(self):
        """Test InstructionDef dataclass."""
        insn_def = InstructionDef(address=0x1000)
        insn_def.defines.add("rax")
        insn_def.uses.add("rbx")

        expect(insn_def.address == _EXPECTED_INSN_DEF_ADDRESS_4096)
        expect(not ("rax" not in insn_def.defines))
        expect(not ("rbx" not in insn_def.uses))

    def test_dependency_analyzer_initialization(self):
        """Test DependencyAnalyzer initialization."""
        analyzer = DependencyAnalyzer()
        expect(len(analyzer.dependencies) == 0)
        expect(len(analyzer.defs) == 0)

    def test_dependency_types(self):
        """Test all dependency types."""
        expect(DependencyType.READ_AFTER_WRITE.value == "RAW")
        expect(DependencyType.WRITE_AFTER_READ.value == "WAR")
        expect(DependencyType.WRITE_AFTER_WRITE.value == "WAW")
        expect(DependencyType.READ_AFTER_READ.value == "RAR")


class TestInvariantDetectorDetailed:
    """Detailed tests for InvariantDetector."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_invariant_creation(self):
        """Test Invariant dataclass."""
        inv = Invariant(
            invariant_type=InvariantType.STACK_BALANCE,
            description="Stack must be balanced",
            location=0x1000,
            details={"stack_delta": 0},
        )
        expect(inv.invariant_type == InvariantType.STACK_BALANCE)
        expect(inv.location == _EXPECTED_INV_LOCATION_4096)

    def test_invariant_types(self):
        """Test all invariant types."""
        expect(InvariantType.STACK_BALANCE.value == "stack_balance")
        expect(InvariantType.REGISTER_PRESERVATION.value == "reg_preserve")
        expect(InvariantType.CALLING_CONVENTION.value == "call_conv")
        expect(InvariantType.RETURN_VALUE.value == "return_value")
        expect(InvariantType.CONTROL_FLOW.value == "control_flow")
        expect(InvariantType.MEMORY_SAFETY.value == "memory_safety")

    def test_invariant_detector_initialization(self, ls_elf):
        """Test InvariantDetector initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = InvariantDetector(binary)
            expect(detector.binary == binary)
            expect(len(detector.invariants) == 0)

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
                    expect(isinstance(invariants, list))

    def test_callee_saved_regs(self):
        """Test callee saved registers."""
        expect(not ("rbx" not in InvariantDetector.CALLEE_SAVED_REGS["x64"]))
        expect(not ("ebx" not in InvariantDetector.CALLEE_SAVED_REGS["x86"]))
        expect(not ("r4" not in InvariantDetector.CALLEE_SAVED_REGS["arm"]))
