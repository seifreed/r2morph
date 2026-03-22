"""
Tests for full control flow flattening pass.

Covers:
- DispatcherBlock dataclass
- CFFConfig configuration
- FullControlFlowFlatteningPass mutations
- State table generation
- Dispatcher code generation
"""

from unittest.mock import MagicMock, patch
from dataclasses import asdict

from r2morph.mutations.full_cff import (
    DispatcherType,
    DispatcherBlock,
    CFFConfig,
    FullControlFlowFlatteningPass,
)


class TestDispatcherType:
    """Test DispatcherType enum."""

    def test_dispatcher_types(self):
        """Test all dispatcher types exist."""
        assert DispatcherType.SWITCH_TABLE.value == "switch_table"
        assert DispatcherType.INDIRECT_JUMP.value == "indirect_jump"
        assert DispatcherType.STATE_MACHINE.value == "state_machine"


class TestDispatcherBlock:
    """Test DispatcherBlock dataclass."""

    def test_basic_dispatcher_block(self):
        """Test basic dispatcher block creation."""
        block = DispatcherBlock(
            state_value=0,
            block_address=0x1000,
            block_size=0x50,
        )
        assert block.state_value == 0
        assert block.block_address == 0x1000
        assert block.block_size == 0x50
        assert block.successor_states == []
        assert block.is_entry is False
        assert block.is_exit is False

    def test_dispatcher_block_with_successors(self):
        """Test dispatcher block with successors."""
        block = DispatcherBlock(
            state_value=1,
            block_address=0x1050,
            block_size=0x30,
            successor_states=[2, 3],
        )
        assert len(block.successor_states) == 2
        assert 2 in block.successor_states
        assert 3 in block.successor_states

    def test_entry_block(self):
        """Test entry block flag."""
        block = DispatcherBlock(
            state_value=0,
            block_address=0x1000,
            block_size=0x50,
            is_entry=True,
        )
        assert block.is_entry is True

    def test_exit_block(self):
        """Test exit block flag."""
        block = DispatcherBlock(
            state_value=5,
            block_address=0x2000,
            block_size=0x10,
            is_exit=True,
        )
        assert block.is_exit is True
        assert len(block.successor_states) == 0


class TestCFFConfig:
    """Test CFFConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = CFFConfig()
        assert config.dispatcher_type == DispatcherType.SWITCH_TABLE
        assert config.state_size == 4
        assert config.randomize_states is True
        assert config.use_opaque_predicates is True
        assert config.create_new_section is False
        assert config.max_functions == 3
        assert config.min_blocks == 3
        assert config.probability == 0.5

    def test_custom_config(self):
        """Test custom configuration values."""
        config = CFFConfig(
            dispatcher_type=DispatcherType.INDIRECT_JUMP,
            state_size=8,
            randomize_states=False,
            use_opaque_predicates=False,
            create_new_section=True,
            max_functions=10,
            min_blocks=5,
            probability=0.7,
        )
        assert config.dispatcher_type == DispatcherType.INDIRECT_JUMP
        assert config.state_size == 8
        assert config.randomize_states is False
        assert config.use_opaque_predicates is False
        assert config.create_new_section is True
        assert config.max_functions == 10
        assert config.min_blocks == 5
        assert config.probability == 0.7

    def test_config_to_dict(self):
        """Test configuration serialization."""
        config = CFFConfig(dispatcher_type=DispatcherType.STATE_MACHINE, max_functions=5)
        d = asdict(config)
        assert d["dispatcher_type"] == DispatcherType.STATE_MACHINE
        assert d["max_functions"] == 5


class TestFullControlFlowFlatteningPass:
    """Test FullControlFlowFlatteningPass."""

    def _create_mock_binary(self):
        """Create a mock binary object."""
        binary = MagicMock()
        binary.path = "/tmp/test"
        binary.is_analyzed.return_value = True
        binary.get_functions.return_value = []
        binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}
        binary.analyze.return_value = None
        return binary

    def _create_mock_cfg(self, num_blocks=5, func_addr=0x1000):
        """Create a mock CFG object."""
        from r2morph.analysis.cfg import ControlFlowGraph, BasicBlock, BlockType

        cfg = MagicMock(spec=ControlFlowGraph)
        cfg.function_address = func_addr
        cfg.blocks = {}

        entry_block = BasicBlock(
            address=func_addr,
            size=32,
            successors=[func_addr + 0x20],
            predecessors=[],
            block_type=BlockType.ENTRY,
        )
        cfg.blocks[func_addr] = entry_block
        cfg.entry_block = entry_block

        for i in range(1, num_blocks):
            block_addr = func_addr + i * 0x20
            block = BasicBlock(
                address=block_addr,
                size=32,
                successors=[func_addr + (i + 1) * 0x20] if i < num_blocks - 1 else [],
                predecessors=[func_addr + (i - 1) * 0x20] if i > 0 else [],
                block_type=BlockType.EXIT if i == num_blocks - 1 else BlockType.NORMAL,
            )
            cfg.blocks[block_addr] = block

        return cfg

    def test_pass_initialization_default(self):
        """Test pass initialization with default config."""
        mutation_pass = FullControlFlowFlatteningPass()
        assert mutation_pass.name == "FullControlFlowFlattening"
        assert mutation_pass.cff_config.dispatcher_type == DispatcherType.SWITCH_TABLE

    def test_pass_initialization_custom(self):
        """Test pass initialization with custom config."""
        mutation_pass = FullControlFlowFlatteningPass(
            config={
                "dispatcher_type": "indirect_jump",
                "max_functions": 5,
                "min_blocks": 4,
            }
        )
        assert mutation_pass.cff_config.dispatcher_type == DispatcherType.INDIRECT_JUMP
        assert mutation_pass.cff_config.max_functions == 5
        assert mutation_pass.cff_config.min_blocks == 4

    def test_apply_no_functions(self):
        """Test apply with no functions."""
        binary = self._create_mock_binary()
        binary.get_functions.return_value = []

        mutation_pass = FullControlFlowFlatteningPass()
        result = mutation_pass.apply(binary)

        assert result["functions_mutated"] == 0
        assert result["mutations_applied"] == 0

    def test_apply_binary_not_analyzed(self):
        """Test apply when binary not analyzed."""
        binary = self._create_mock_binary()
        binary.is_analyzed.return_value = False
        binary.get_functions.return_value = []

        mutation_pass = FullControlFlowFlatteningPass()
        result = mutation_pass.apply(binary)

        binary.analyze.assert_called_once()
        assert result["functions_mutated"] == 0

    def test_create_dispatcher_blocks(self):
        """Test dispatcher block creation."""
        self._create_mock_binary()
        mutation_pass = FullControlFlowFlatteningPass()
        cfg = self._create_mock_cfg(num_blocks=5)

        blocks = mutation_pass._create_dispatcher_blocks(cfg)

        assert len(blocks) == 5
        assert blocks[0].is_entry is True
        assert blocks[-1].is_exit is True

    def test_create_dispatcher_blocks_exit_detection(self):
        """Test that exit blocks are correctly identified."""
        self._create_mock_binary()
        mutation_pass = FullControlFlowFlatteningPass()
        cfg = self._create_mock_cfg(num_blocks=3)

        blocks = mutation_pass._create_dispatcher_blocks(cfg)

        assert blocks[0].is_entry is True
        assert blocks[2].is_exit is True
        assert blocks[1].is_exit is False

    def test_generate_state_table(self):
        """Test state table generation."""
        mutation_pass = FullControlFlowFlatteningPass()

        dispatcher_blocks = [
            DispatcherBlock(state_value=0, block_address=0x1000, block_size=32, successor_states=[1]),
            DispatcherBlock(state_value=1, block_address=0x1020, block_size=32, successor_states=[2]),
            DispatcherBlock(state_value=2, block_address=0x1040, block_size=32, is_exit=True),
        ]

        state_table = mutation_pass._generate_state_table(dispatcher_blocks)

        assert 0 in state_table
        assert state_table[0] == (1, None)
        assert state_table[1] == (2, None)
        assert state_table[2] == (-1, None)

    def test_generate_state_table_conditional(self):
        """Test state table with conditional successors."""
        mutation_pass = FullControlFlowFlatteningPass()

        dispatcher_blocks = [
            DispatcherBlock(state_value=0, block_address=0x1000, block_size=32, successor_states=[1, 2]),
            DispatcherBlock(state_value=1, block_address=0x1020, block_size=32, successor_states=[3]),
            DispatcherBlock(state_value=2, block_address=0x1040, block_size=32, successor_states=[3]),
            DispatcherBlock(state_value=3, block_address=0x1060, block_size=32, is_exit=True),
        ]

        state_table = mutation_pass._generate_state_table(dispatcher_blocks)

        assert state_table[0] == (1, 2)
        assert state_table[1] == (3, None)
        assert state_table[2] == (3, None)
        assert state_table[3] == (-1, None)

    def test_generate_x86_dispatcher_64bit(self):
        """Test x86_64 dispatcher generation."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (2, None),
            2: (-1, None),
        }

        instructions = mutation_pass._generate_x86_dispatcher(state_table, bits=64)

        assert len(instructions) > 0
        assert "mov rax" in instructions[0]
        assert "dispatcher_loop:" in instructions

    def test_generate_x86_dispatcher_32bit(self):
        """Test x86 32-bit dispatcher generation."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (-1, None),
        }

        instructions = mutation_pass._generate_x86_dispatcher(state_table, bits=32)

        assert len(instructions) > 0
        assert "mov eax" in instructions[0]

    def test_generate_arm_dispatcher_64bit(self):
        """Test ARM64 dispatcher generation."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (2, None),
            2: (-1, None),
        }

        instructions = mutation_pass._generate_arm_dispatcher(state_table, bits=64)

        assert len(instructions) > 0
        assert "mov x0" in instructions[0]
        assert "dispatcher_loop:" in instructions

    def test_generate_arm_dispatcher_32bit(self):
        """Test ARM 32-bit dispatcher generation."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (-1, None),
        }

        instructions = mutation_pass._generate_arm_dispatcher(state_table, bits=32)

        assert len(instructions) > 0
        assert "mov r0" in instructions[0]

    def test_generate_dispatcher_code_unsupported_arch(self):
        """Test dispatcher code for unsupported architecture."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {0: (1, None), 1: (-1, None)}
        instructions = mutation_pass._generate_dispatcher_code(state_table, "mips", 64, 0x1000)

        assert instructions is None

    def test_generate_dispatcher_code_x86(self):
        """Test dispatcher code generation for x86."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (2, None),
            2: (-1, None),
        }

        instructions = mutation_pass._generate_dispatcher_code(state_table, "x86", 32, 0x1000)

        assert instructions is not None
        assert len(instructions) > 0

    def test_generate_dispatcher_code_arm(self):
        """Test dispatcher code generation for ARM."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (-1, None),
        }

        instructions = mutation_pass._generate_dispatcher_code(state_table, "arm64", 64, 0x1000)

        assert instructions is not None
        assert len(instructions) > 0

    def test_select_candidates_small_function(self):
        """Test candidate selection skips small functions."""
        binary = self._create_mock_binary()
        binary.get_functions.return_value = [
            {"offset": 0x1000, "name": "small_func", "size": 10},
        ]
        binary.get_basic_blocks.return_value = [{"addr": 0x1000}]

        mutation_pass = FullControlFlowFlatteningPass()
        candidates = mutation_pass._select_candidates(binary, binary.get_functions.return_value)

        assert len(candidates) == 0

    def test_select_candidates_import_function(self):
        """Test candidate selection skips import functions."""
        binary = self._create_mock_binary()
        binary.get_functions.return_value = [
            {"offset": 0x1000, "name": "sym.imp.printf", "size": 100},
        ]

        mutation_pass = FullControlFlowFlatteningPass()
        candidates = mutation_pass._select_candidates(binary, binary.get_functions.return_value)

        assert len(candidates) == 0

    def test_select_candidates_valid_function(self):
        """Test candidate selection accepts valid functions."""
        binary = self._create_mock_binary()
        binary.get_functions.return_value = [
            {"offset": 0x1000, "name": "valid_func", "size": 100},
        ]
        binary.get_basic_blocks.return_value = [
            {"addr": 0x1000},
            {"addr": 0x1020},
            {"addr": 0x1040},
            {"addr": 0x1060},
        ]

        mutation_pass = FullControlFlowFlatteningPass()
        candidates = mutation_pass._select_candidates(binary, binary.get_functions.return_value)

        assert len(candidates) == 1
        assert candidates[0]["_block_count"] == 4

    def test_assemble_dispatcher(self):
        """Test dispatcher assembly."""
        binary = self._create_mock_binary()
        binary.assemble.return_value = b"\x90"

        mutation_pass = FullControlFlowFlatteningPass()
        instructions = ["nop", "nop", "nop"]

        result = mutation_pass._assemble_dispatcher(binary, instructions)

        assert result is not None
        assert len(result) == 3

    def test_assemble_dispatcher_failure(self):
        """Test dispatcher assembly failure handling."""
        binary = self._create_mock_binary()
        binary.assemble.side_effect = Exception("Assembly error")

        mutation_pass = FullControlFlowFlatteningPass()
        instructions = ["invalid_instruction"]

        result = mutation_pass._assemble_dispatcher(binary, instructions)

        assert result is None

    def test_patch_function_blocks(self):
        """Test function block patching."""
        binary = self._create_mock_binary()
        binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}
        binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "size": 5},
            {"offset": 0x1005, "size": 5},
            {"offset": 0x100A, "size": 5},
        ]
        binary.write_bytes.return_value = None

        mutation_pass = FullControlFlowFlatteningPass()
        cfg = self._create_mock_cfg(num_blocks=3)

        dispatcher_blocks = [
            DispatcherBlock(state_value=0, block_address=0x1000, block_size=0x10, successor_states=[1]),
            DispatcherBlock(state_value=1, block_address=0x1010, block_size=0x10, successor_states=[2]),
            DispatcherBlock(state_value=2, block_address=0x1020, block_size=0x10, is_exit=True),
        ]

        state_table = {0: (1, None), 1: (2, None), 2: (-1, None)}

        patches = mutation_pass._patch_function_blocks(binary, cfg, dispatcher_blocks, state_table, 0x2000)

        assert patches >= 0

    def test_apply_with_valid_function(self):
        """Test apply with a valid function candidate."""
        binary = self._create_mock_binary()
        binary.get_functions.return_value = [
            {"offset": 0x1000, "name": "test_func", "size": 100},
        ]
        binary.get_basic_blocks.return_value = [
            {"addr": 0x1000},
            {"addr": 0x1020},
            {"addr": 0x1040},
            {"addr": 0x1060},
        ]

        mock_cfg = self._create_mock_cfg(num_blocks=4)
        mock_allocation = MagicMock()
        mock_allocation.address = 0x2000

        with (
            patch("r2morph.mutations.full_cff.CFGBuilder") as MockCFGBuilder,
            patch("r2morph.mutations.full_cff.CodeCaveInjector") as MockCaveInjector,
        ):
            mock_cfg_builder = MagicMock()
            mock_cfg_builder.build_cfg.return_value = mock_cfg
            MockCFGBuilder.return_value = mock_cfg_builder

            mock_cave = MagicMock()
            mock_cave.insert_code.return_value = mock_allocation
            MockCaveInjector.return_value = mock_cave

            binary.assemble.return_value = b"\x90"
            binary.write_bytes.return_value = None
            binary.get_function_disasm.return_value = [
                {"offset": 0x1000, "size": 5},
            ]

            mutation_pass = FullControlFlowFlatteningPass(config={"probability": 1.0})
            result = mutation_pass.apply(binary)

            assert isinstance(result, dict)
            assert "functions_mutated" in result
            assert "mutations_applied" in result

    def test_apply_probability_check(self):
        """Test that probability check affects function selection."""
        binary = self._create_mock_binary()
        binary.get_functions.return_value = [
            {"offset": 0x1000, "name": "test_func", "size": 100},
        ]
        binary.get_basic_blocks.return_value = [
            {"addr": 0x1000},
            {"addr": 0x1020},
            {"addr": 0x1040},
        ]

        mutation_pass = FullControlFlowFlatteningPass(config={"probability": 0.0})
        result = mutation_pass.apply(binary)

        assert result["functions_mutated"] == 0

    def test_empty_state_table(self):
        """Test handling of empty state table."""
        mutation_pass = FullControlFlowFlatteningPass()

        instructions = mutation_pass._generate_x86_dispatcher({}, bits=64)

        assert instructions == []

    def test_min_blocks_requirement(self):
        """Test that functions with too few blocks are skipped."""
        binary = self._create_mock_binary()
        binary.get_functions.return_value = [
            {"offset": 0x1000, "name": "small_func", "size": 100},
        ]
        binary.get_basic_blocks.return_value = [
            {"addr": 0x1000},
        ]

        mutation_pass = FullControlFlowFlatteningPass(config={"min_blocks": 3})
        candidates = mutation_pass._select_candidates(binary, binary.get_functions.return_value)

        assert len(candidates) == 0
