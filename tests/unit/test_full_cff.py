"""
Tests for full control flow flattening pass.

Covers:
- DispatcherBlock dataclass
- CFFConfig configuration
- FullControlFlowFlatteningPass mutations
- State table generation
- Dispatcher code generation
"""

import importlib
from dataclasses import asdict
from pathlib import Path

from r2morph.mutations.full_cff import (
    CFFConfig,
    DispatcherBlock,
    DispatcherType,
    FullControlFlowFlatteningPass,
)
from tests.utils.assertions import expect

_EXPECTED_BLOCK_BLOCK_ADDRESS_4096 = 0x1000
_EXPECTED_BLOCK_BLOCK_SIZE_80 = 0x50
_EXPECTED_BLOCK_SUCCESSOR_STATES_2 = 2
_EXPECTED_BLOCK_SUCCESSOR_STATES_3 = 3
_EXPECTED_CANDIDATES_0_BLOCK_COUNT_4 = 4
_EXPECTED_CONFIG_MAX_FUNCTIONS_10 = 10
_EXPECTED_CONFIG_MAX_FUNCTIONS_3 = 3
_EXPECTED_CONFIG_MIN_BLOCKS_3 = 3
_EXPECTED_CONFIG_MIN_BLOCKS_5 = 5
_EXPECTED_CONFIG_PROBABILITY_0_5 = 0.5
_EXPECTED_CONFIG_PROBABILITY_0_7 = 0.7
_EXPECTED_CONFIG_STATE_SIZE_4 = 4
_EXPECTED_CONFIG_STATE_SIZE_8 = 8
_EXPECTED_D_MAX_FUNCTIONS_5 = 5
_EXPECTED_LEN_BLOCKS_5 = 5
_EXPECTED_LEN_BLOCK_SUCCESSOR_STATES_2 = 2
_EXPECTED_LEN_RESULT_3 = 3
_EXPECTED_MUTATION_PASS_CFF_CONFIG_MAX_FUNCTIONS_5 = 5
_EXPECTED_MUTATION_PASS_CFF_CONFIG_MIN_BLOCKS_4 = 4


class _Binary:
    def __init__(self) -> None:
        self.path = Path("test-data/test")
        self.analyzed = True
        self.analyze_calls = 0
        self.functions: list[dict[str, object]] = []
        self.arch_info: dict[str, object] = {"arch": "x86_64", "bits": 64}
        self.basic_blocks: list[dict[str, object]] = []
        self.disassembly: list[dict[str, object]] = []
        self.assembled: bytes | None = b"\x90"
        self.assembly_error: Exception | None = None
        self.writes: list[tuple[int, bytes]] = []

    def is_analyzed(self) -> bool:
        return self.analyzed

    def analyze(self) -> None:
        self.analyzed = True
        self.analyze_calls += 1

    def get_functions(self) -> list[dict[str, object]]:
        return self.functions

    def get_arch_info(self) -> dict[str, object]:
        return self.arch_info

    def get_basic_blocks(self, address: int) -> list[dict[str, object]]:
        return self.basic_blocks

    def get_function_disasm(self, address: int) -> list[dict[str, object]]:
        return self.disassembly

    def assemble(self, instruction: str, function_addr: int | None = None) -> bytes | None:
        if self.assembly_error is not None:
            raise self.assembly_error
        return self.assembled

    def write_bytes(self, address: int, data: bytes) -> None:
        self.writes.append((address, data))


class TestDispatcherType:
    """Test DispatcherType enum."""

    def test_dispatcher_types(self):
        """Test all dispatcher types exist."""
        expect(DispatcherType.SWITCH_TABLE.value == "switch_table")
        expect(DispatcherType.INDIRECT_JUMP.value == "indirect_jump")
        expect(DispatcherType.STATE_MACHINE.value == "state_machine")


class TestDispatcherBlock:
    """Test DispatcherBlock dataclass."""

    def test_basic_dispatcher_block(self):
        """Test basic dispatcher block creation."""
        block = DispatcherBlock(
            state_value=0,
            block_address=0x1000,
            block_size=0x50,
        )
        expect(block.state_value == 0)
        expect(block.block_address == _EXPECTED_BLOCK_BLOCK_ADDRESS_4096)
        expect(block.block_size == _EXPECTED_BLOCK_BLOCK_SIZE_80)
        expect(block.successor_states == [])
        expect(not (block.is_entry is not False))
        expect(not (block.is_exit is not False))

    def test_dispatcher_block_with_successors(self):
        """Test dispatcher block with successors."""
        block = DispatcherBlock(
            state_value=1,
            block_address=0x1050,
            block_size=0x30,
            successor_states=[2, 3],
        )
        expect(len(block.successor_states) == _EXPECTED_LEN_BLOCK_SUCCESSOR_STATES_2)
        expect(not (_EXPECTED_BLOCK_SUCCESSOR_STATES_2 not in block.successor_states))
        expect(not (_EXPECTED_BLOCK_SUCCESSOR_STATES_3 not in block.successor_states))

    def test_entry_block(self):
        """Test entry block flag."""
        block = DispatcherBlock(
            state_value=0,
            block_address=0x1000,
            block_size=0x50,
            is_entry=True,
        )
        expect(not (block.is_entry is not True))

    def test_exit_block(self):
        """Test exit block flag."""
        block = DispatcherBlock(
            state_value=5,
            block_address=0x2000,
            block_size=0x10,
            is_exit=True,
        )
        expect(not (block.is_exit is not True))
        expect(len(block.successor_states) == 0)


class TestCFFConfig:
    """Test CFFConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = CFFConfig()
        expect(config.dispatcher_type == DispatcherType.SWITCH_TABLE)
        expect(config.state_size == _EXPECTED_CONFIG_STATE_SIZE_4)
        expect(not (config.randomize_states is not True))
        expect(not (config.use_opaque_predicates is not True))
        expect(not (config.create_new_section is not False))
        expect(config.max_functions == _EXPECTED_CONFIG_MAX_FUNCTIONS_3)
        expect(config.min_blocks == _EXPECTED_CONFIG_MIN_BLOCKS_3)
        expect(config.probability == _EXPECTED_CONFIG_PROBABILITY_0_5)

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
        expect(config.dispatcher_type == DispatcherType.INDIRECT_JUMP)
        expect(config.state_size == _EXPECTED_CONFIG_STATE_SIZE_8)
        expect(not (config.randomize_states is not False))
        expect(not (config.use_opaque_predicates is not False))
        expect(not (config.create_new_section is not True))
        expect(config.max_functions == _EXPECTED_CONFIG_MAX_FUNCTIONS_10)
        expect(config.min_blocks == _EXPECTED_CONFIG_MIN_BLOCKS_5)
        expect(config.probability == _EXPECTED_CONFIG_PROBABILITY_0_7)

    def test_config_to_dict(self):
        """Test configuration serialization."""
        config = CFFConfig(dispatcher_type=DispatcherType.STATE_MACHINE, max_functions=5)
        d = asdict(config)
        expect(d["dispatcher_type"] == DispatcherType.STATE_MACHINE)
        expect(d["max_functions"] == _EXPECTED_D_MAX_FUNCTIONS_5)


class TestFullControlFlowFlatteningPass:
    """Test FullControlFlowFlatteningPass."""

    def _create_mock_binary(self):
        """Create an in-memory binary object."""
        return _Binary()

    def _create_mock_cfg(self, num_blocks=5, func_addr=0x1000):
        """Create a mock CFG object."""
        basic_block = importlib.import_module("r2morph.analysis.cfg").BasicBlock
        block_type = importlib.import_module("r2morph.analysis.cfg").BlockType
        control_flow_graph = importlib.import_module("r2morph.analysis.cfg").ControlFlowGraph

        cfg = control_flow_graph(function_address=func_addr, function_name="test")

        entry_block = basic_block(
            address=func_addr,
            size=32,
            successors=[func_addr + 0x20],
            predecessors=[],
            block_type=block_type.ENTRY,
        )
        cfg.add_block(entry_block)

        for i in range(1, num_blocks):
            block_addr = func_addr + i * 0x20
            block = basic_block(
                address=block_addr,
                size=32,
                successors=[func_addr + (i + 1) * 0x20] if i < num_blocks - 1 else [],
                predecessors=[func_addr + (i - 1) * 0x20] if i > 0 else [],
                block_type=block_type.EXIT if i == num_blocks - 1 else block_type.NORMAL,
            )
            cfg.add_block(block)

        return cfg

    def test_pass_initialization_default(self):
        """Test pass initialization with default config."""
        mutation_pass = FullControlFlowFlatteningPass()
        expect(mutation_pass.name == "FullControlFlowFlattening")
        expect(mutation_pass.cff_config.dispatcher_type == DispatcherType.SWITCH_TABLE)

    def test_pass_initialization_custom(self):
        """Test pass initialization with custom config."""
        mutation_pass = FullControlFlowFlatteningPass(
            config={
                "dispatcher_type": "indirect_jump",
                "max_functions": 5,
                "min_blocks": 4,
            }
        )
        expect(mutation_pass.cff_config.dispatcher_type == DispatcherType.INDIRECT_JUMP)
        expect(mutation_pass.cff_config.max_functions == _EXPECTED_MUTATION_PASS_CFF_CONFIG_MAX_FUNCTIONS_5)
        expect(mutation_pass.cff_config.min_blocks == _EXPECTED_MUTATION_PASS_CFF_CONFIG_MIN_BLOCKS_4)

    def test_apply_no_functions(self):
        """Test apply with no functions."""
        binary = self._create_mock_binary()

        mutation_pass = FullControlFlowFlatteningPass()
        result = mutation_pass.apply(binary)

        expect(result["functions_mutated"] == 0)
        expect(result["mutations_applied"] == 0)

    def test_apply_binary_not_analyzed(self):
        """Test apply when binary not analyzed."""
        binary = self._create_mock_binary()
        binary.analyzed = False

        mutation_pass = FullControlFlowFlatteningPass()
        result = mutation_pass.apply(binary)

        expect(binary.analyze_calls == 1)
        expect(result["functions_mutated"] == 0)

    def test_create_dispatcher_blocks(self):
        """Test dispatcher block creation."""
        self._create_mock_binary()
        mutation_pass = FullControlFlowFlatteningPass()
        cfg = self._create_mock_cfg(num_blocks=5)

        blocks = mutation_pass._create_dispatcher_blocks(cfg)

        expect(len(blocks) == _EXPECTED_LEN_BLOCKS_5)
        expect(not (blocks[0].is_entry is not True))
        expect(not (blocks[-1].is_exit is not True))

    def test_create_dispatcher_blocks_exit_detection(self):
        """Test that exit blocks are correctly identified."""
        self._create_mock_binary()
        mutation_pass = FullControlFlowFlatteningPass()
        cfg = self._create_mock_cfg(num_blocks=3)

        blocks = mutation_pass._create_dispatcher_blocks(cfg)

        expect(not (blocks[0].is_entry is not True))
        expect(not (blocks[2].is_exit is not True))
        expect(not (blocks[1].is_exit is not False))

    def test_generate_state_table(self):
        """Test state table generation."""
        mutation_pass = FullControlFlowFlatteningPass()

        dispatcher_blocks = [
            DispatcherBlock(state_value=0, block_address=0x1000, block_size=32, successor_states=[1]),
            DispatcherBlock(state_value=1, block_address=0x1020, block_size=32, successor_states=[2]),
            DispatcherBlock(state_value=2, block_address=0x1040, block_size=32, is_exit=True),
        ]

        state_table = mutation_pass._generate_state_table(dispatcher_blocks)

        expect(not (0 not in state_table))
        expect(state_table[0] == (1, None))
        expect(state_table[1] == (2, None))
        expect(state_table[2] == (-1, None))

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

        expect(state_table[0] == (1, 2))
        expect(state_table[1] == (3, None))
        expect(state_table[2] == (3, None))
        expect(state_table[3] == (-1, None))

    def test_generate_x86_dispatcher_64bit(self):
        """Test x86_64 dispatcher generation."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (2, None),
            2: (-1, None),
        }

        instructions = mutation_pass._generate_x86_dispatcher(state_table, bits=64)

        expect(not (len(instructions) <= 0))
        expect(not ("mov rax" not in instructions[0]))
        expect(not ("dispatcher_loop:" not in instructions))

    def test_generate_x86_dispatcher_32bit(self):
        """Test x86 32-bit dispatcher generation."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (-1, None),
        }

        instructions = mutation_pass._generate_x86_dispatcher(state_table, bits=32)

        expect(not (len(instructions) <= 0))
        expect(not ("mov eax" not in instructions[0]))

    def test_generate_arm_dispatcher_64bit(self):
        """Test ARM64 dispatcher generation."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (2, None),
            2: (-1, None),
        }

        instructions = mutation_pass._generate_arm_dispatcher(state_table, bits=64)

        expect(not (len(instructions) <= 0))
        expect(not ("mov x0" not in instructions[0]))
        expect(not ("dispatcher_loop:" not in instructions))

    def test_generate_arm_dispatcher_32bit(self):
        """Test ARM 32-bit dispatcher generation."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (-1, None),
        }

        instructions = mutation_pass._generate_arm_dispatcher(state_table, bits=32)

        expect(not (len(instructions) <= 0))
        expect(not ("mov r0" not in instructions[0]))

    def test_generate_dispatcher_code_unsupported_arch(self):
        """Test dispatcher code for unsupported architecture."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {0: (1, None), 1: (-1, None)}
        instructions = mutation_pass._generate_dispatcher_code(state_table, "mips", 64, 0x1000)

        expect(not (instructions is not None))

    def test_generate_dispatcher_code_x86(self):
        """Test dispatcher code generation for x86."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (2, None),
            2: (-1, None),
        }

        instructions = mutation_pass._generate_dispatcher_code(state_table, "x86", 32, 0x1000)

        expect(instructions is not None)
        expect(not (len(instructions) <= 0))

    def test_generate_dispatcher_code_arm(self):
        """Test dispatcher code generation for ARM."""
        mutation_pass = FullControlFlowFlatteningPass()

        state_table = {
            0: (1, None),
            1: (-1, None),
        }

        instructions = mutation_pass._generate_dispatcher_code(state_table, "arm64", 64, 0x1000)

        expect(instructions is not None)
        expect(not (len(instructions) <= 0))

    def test_select_candidates_small_function(self):
        """Test candidate selection skips small functions."""
        binary = self._create_mock_binary()
        binary.functions = [
            {"offset": 0x1000, "name": "small_func", "size": 10},
        ]
        binary.basic_blocks = [{"addr": 0x1000}]

        mutation_pass = FullControlFlowFlatteningPass()
        candidates = mutation_pass._select_candidates(binary, binary.functions)

        expect(len(candidates) == 0)

    def test_select_candidates_import_function(self):
        """Test candidate selection skips import functions."""
        binary = self._create_mock_binary()
        binary.functions = [
            {"offset": 0x1000, "name": "sym.imp.printf", "size": 100},
        ]

        mutation_pass = FullControlFlowFlatteningPass()
        candidates = mutation_pass._select_candidates(binary, binary.functions)

        expect(len(candidates) == 0)

    def test_select_candidates_valid_function(self):
        """Test candidate selection accepts valid functions."""
        binary = self._create_mock_binary()
        binary.functions = [
            {"offset": 0x1000, "name": "valid_func", "size": 100},
        ]
        binary.basic_blocks = [
            {"addr": 0x1000},
            {"addr": 0x1020},
            {"addr": 0x1040},
            {"addr": 0x1060},
        ]

        mutation_pass = FullControlFlowFlatteningPass()
        candidates = mutation_pass._select_candidates(binary, binary.functions)

        expect(len(candidates) == 1)
        expect(candidates[0]["_block_count"] == _EXPECTED_CANDIDATES_0_BLOCK_COUNT_4)

    def test_assemble_dispatcher(self):
        """Test dispatcher assembly."""
        binary = self._create_mock_binary()
        binary.assembled = b"\x90"

        mutation_pass = FullControlFlowFlatteningPass()
        instructions = ["nop", "nop", "nop"]

        result = mutation_pass._assemble_dispatcher(binary, instructions)

        expect(result is not None)
        expect(len(result) == _EXPECTED_LEN_RESULT_3)

    def test_assemble_dispatcher_failure(self):
        """Test dispatcher assembly failure handling."""
        binary = self._create_mock_binary()
        binary.assembly_error = RuntimeError("Assembly error")

        mutation_pass = FullControlFlowFlatteningPass()
        instructions = ["invalid_instruction"]

        result = mutation_pass._assemble_dispatcher(binary, instructions)

        expect(not (result is not None))

    def test_patch_function_blocks(self):
        """Test function block patching."""
        binary = self._create_mock_binary()
        binary.arch_info = {"arch": "x86_64", "bits": 64}
        binary.disassembly = [
            {"offset": 0x1000, "size": 5},
            {"offset": 0x1005, "size": 5},
            {"offset": 0x100A, "size": 5},
        ]
        mutation_pass = FullControlFlowFlatteningPass()
        cfg = self._create_mock_cfg(num_blocks=3)

        dispatcher_blocks = [
            DispatcherBlock(state_value=0, block_address=0x1000, block_size=0x10, successor_states=[1]),
            DispatcherBlock(state_value=1, block_address=0x1010, block_size=0x10, successor_states=[2]),
            DispatcherBlock(state_value=2, block_address=0x1020, block_size=0x10, is_exit=True),
        ]

        state_table = {0: (1, None), 1: (2, None), 2: (-1, None)}

        patches = mutation_pass._patch_function_blocks(binary, cfg, dispatcher_blocks, state_table, 0x2000)

        expect(not (patches < 0))

    def test_apply_probability_check(self):
        """Test that probability check affects function selection."""
        binary = self._create_mock_binary()
        binary.functions = [
            {"offset": 0x1000, "name": "test_func", "size": 100},
        ]
        binary.basic_blocks = [
            {"addr": 0x1000},
            {"addr": 0x1020},
            {"addr": 0x1040},
        ]

        mutation_pass = FullControlFlowFlatteningPass(config={"probability": 0.0})
        result = mutation_pass.apply(binary)

        expect(result["functions_mutated"] == 0)

    def test_empty_state_table(self):
        """Test handling of empty state table."""
        mutation_pass = FullControlFlowFlatteningPass()

        instructions = mutation_pass._generate_x86_dispatcher({}, bits=64)

        expect(instructions == [])

    def test_min_blocks_requirement(self):
        """Test that functions with too few blocks are skipped."""
        binary = self._create_mock_binary()
        binary.functions = [
            {"offset": 0x1000, "name": "small_func", "size": 100},
        ]
        binary.basic_blocks = [
            {"addr": 0x1000},
        ]

        mutation_pass = FullControlFlowFlatteningPass(config={"min_blocks": 3})
        candidates = mutation_pass._select_candidates(binary, binary.functions)

        expect(len(candidates) == 0)
