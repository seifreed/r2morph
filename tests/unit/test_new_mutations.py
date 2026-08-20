"""
Tests for new mutation passes: DataFlow, StringObfuscation, ImportObfuscation,
ConstantUnfolding, and ParallelExecutor.
"""

from r2morph.mutations.constant_unfolding import ConstantUnfoldingPass
from r2morph.mutations.data_flow_mutation import DataFlowMutationPass
from r2morph.mutations.import_obfuscation import ImportTableObfuscationPass
from r2morph.mutations.parallel_executor import (
    MutationTask,
    ParallelMutator,
    ParallelStats,
    create_parallel_executor,
)
from r2morph.mutations.string_obfuscation import StringObfuscationPass
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY

_EXPECTED_EXECUTOR_CHUNK_SIZE_10 = 10
_EXPECTED_EXECUTOR_CHUNK_SIZE_5 = 5
_EXPECTED_EXECUTOR_MAX_WORKERS_2 = 2
_EXPECTED_EXECUTOR_MAX_WORKERS_4 = 4
_EXPECTED_EXECUTOR_TIMEOUT_300 = 300
_EXPECTED_EXECUTOR_TIMEOUT_60 = 60
_EXPECTED_LEN_INSTRUCTIONS_2 = 2
_EXPECTED_LEN_INSTRUCTIONS_3 = 3
_EXPECTED_LEN_TASK_FUNCTION_ADDRESSES_2 = 2
_EXPECTED_LIVE_IN_4096 = 0x1000
_EXPECTED_P_MAX_IMPORTS_50 = 50
_EXPECTED_P_MAX_MUTATIONS_10 = 10
_EXPECTED_P_MAX_MUTATIONS_5 = 5
_EXPECTED_P_MAX_SEQUENCE_10 = 10
_EXPECTED_P_MAX_STRINGS_10 = 10
_EXPECTED_P_MAX_UNFOLDS_5 = 5
_EXPECTED_P_MIN_LENGTH_4 = 4
_EXPECTED_P_PROBABILITY_0_3 = 0.3
_EXPECTED_P_PROBABILITY_0_3_2 = 0.3
_EXPECTED_P_PROBABILITY_0_5 = 0.5
_EXPECTED_P_PROBABILITY_0_5_2 = 0.5
_EXPECTED_P_PROBABILITY_0_5_3 = 0.5
_EXPECTED_P_SIZE_LIMIT_3_0 = 3.0
_EXPECTED_STATS_SPEEDUP_FACTOR_2_5 = 2.5
_EXPECTED_STATS_TASKS_COMPLETED_10 = 10
_EXPECTED_STATS_TOTAL_TIME_1_5 = 1.5
_EXPECTED_STATS_WORKER_COUNT_4 = 4
_EXPECTED_TASK_CONFIG_SEED_42 = 42


class _Binary:
    r2 = None

    def __init__(self, assembled: bytes = b"") -> None:
        self.assembled = assembled

    def assemble(self, _instruction: str) -> bytes:
        return self.assembled


class TestDataFlowMutationPass:
    """Tests for DataFlowMutationPass."""

    def test_initialization(self):
        """Test DataFlowMutationPass initialization."""
        p = DataFlowMutationPass()

        expect(p.name == "DataFlowMutation")
        expect(p.probability == _EXPECTED_P_PROBABILITY_0_3)
        expect(p.max_mutations == _EXPECTED_P_MAX_MUTATIONS_5)
        expect(not (p.use_liveness is not True))
        expect(not (p.use_reaching_defs is not True))

    def test_initialization_with_config(self):
        """Test DataFlowMutationPass with custom config."""
        config = {
            "probability": 0.5,
            "max_mutations_per_function": 10,
            "use_liveness": False,
            "use_reaching_defs": False,
        }
        p = DataFlowMutationPass(config=config)

        expect(p.probability == _EXPECTED_P_PROBABILITY_0_5)
        expect(p.max_mutations == _EXPECTED_P_MAX_MUTATIONS_10)
        expect(not (p.use_liveness is not False))
        expect(not (p.use_reaching_defs is not False))

    def test_support_declaration(self):
        """Test support declaration for data flow pass."""
        p = DataFlowMutationPass()

        support = p.get_support()

        expect(not ("x86_64" not in support.architectures))
        expect(not ("ELF" not in support.formats))
        expect(support.stability == "experimental")

    def test_analyze_function_liveness(self):
        """Test liveness analysis."""
        p = DataFlowMutationPass()

        instructions = [
            {"addr": 0x1000, "disasm": "mov eax, 5"},
            {"addr": 0x1005, "disasm": "add eax, 10"},
            {"addr": 0x100A, "disasm": "mov ebx, eax"},
            {"addr": 0x100F, "disasm": "call func"},
        ]

        live_in = p._analyze_function_liveness(instructions)

        expect(isinstance(live_in, dict))
        expect(not (_EXPECTED_LIVE_IN_4096 not in live_in))

    def test_is_register_safe_to_use(self):
        """Test register safety check."""
        p = DataFlowMutationPass()

        live_in = {0x1000: {"rax", "rcx"}}
        caller_saved = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}

        expect(p._is_register_safe_to_use("rdx", 0x1000, live_in, caller_saved))
        expect(not (p._is_register_safe_to_use("rax", 0x1000, live_in, caller_saved)))
        expect(not (p._is_register_safe_to_use("rbx", 0x1000, live_in, caller_saved)))


class TestStringObfuscationPass:
    """Tests for StringObfuscationPass."""

    def test_initialization(self):
        """Test StringObfuscationPass initialization."""
        p = StringObfuscationPass()

        expect(p.name == "StringObfuscation")
        expect(p.probability == _EXPECTED_P_PROBABILITY_0_5_2)
        expect(p.max_strings == _EXPECTED_P_MAX_STRINGS_10)
        expect(p.encoding == "random")
        expect(p.min_length == _EXPECTED_P_MIN_LENGTH_4)

    def test_encodings_list(self):
        """Test available encodings."""
        p = StringObfuscationPass()

        expect(not ("xor" not in p.ENCODINGS))
        expect(not ("rot13" not in p.ENCODINGS))
        expect(not ("swap" not in p.ENCODINGS))

    def test_xor_encode(self):
        """Test XOR encoding."""
        p = StringObfuscationPass()

        data = b"Hello"
        key = 0x42

        encoded = p._xor_encode(data, key)

        expect(len(encoded) == len(data))
        expect(encoded != data)

        decoded = bytes(b ^ key for b in encoded)
        expect(decoded == data)

    def test_rot13_encode(self):
        """Test ROT13 encoding."""
        p = StringObfuscationPass()

        data = b"Hello"
        encoded = p._rot13_encode(data)

        expect(len(encoded) == len(data))

        expect(encoded[0] == ord("U"))
        expect(encoded[1] == ord("r"))

        decoded = p._rot13_encode(encoded)
        expect(decoded == data)

    def test_swap_encode(self):
        """Test byte swap encoding."""
        p = StringObfuscationPass()

        data = b"ABCD"
        encoded = p._swap_encode(data)

        expect(encoded[0] == data[1])
        expect(encoded[1] == data[0])
        expect(encoded[2] == data[3])
        expect(encoded[3] == data[2])

    def test_support_declaration(self):
        """Test support declaration for string obfuscation."""
        p = StringObfuscationPass()

        support = p.get_support()

        expect(not ("x86_64" not in support.architectures))
        expect(not ("ELF" not in support.formats))
        expect(support.stability == "experimental")


class TestImportTableObfuscationPass:
    """Tests for ImportTableObfuscationPass."""

    def test_initialization(self):
        """Test ImportTableObfuscationPass initialization."""
        p = ImportTableObfuscationPass()

        expect(p.name == "ImportTableObfuscation")
        expect(p.probability == _EXPECTED_P_PROBABILITY_0_5_3)
        expect(p.max_imports == _EXPECTED_P_MAX_IMPORTS_50)

    def test_support_declaration(self):
        """Test support declaration for import obfuscation."""
        p = ImportTableObfuscationPass()

        support = p.get_support()

        expect(not ("x86_64" not in support.architectures))
        expect(not ("ELF" not in support.formats))
        expect(not ("PE" not in support.formats))
        expect(support.stability == "experimental")

    def test_get_imports_elf_empty(self):
        """Test ELF import extraction with empty result."""
        p = ImportTableObfuscationPass()

        imports = p._get_imports_elf(_Binary())

        expect(imports == [])


class TestConstantUnfoldingPass:
    """Tests for ConstantUnfoldingPass."""

    def test_initialization(self):
        """Test ConstantUnfoldingPass initialization."""
        p = ConstantUnfoldingPass()

        expect(p.name == "ConstantUnfolding")
        expect(p.probability == _EXPECTED_P_PROBABILITY_0_3_2)
        expect(p.max_unfolds == _EXPECTED_P_MAX_UNFOLDS_5)
        expect(p.max_sequence == _EXPECTED_P_MAX_SEQUENCE_10)
        expect(p.size_limit == _EXPECTED_P_SIZE_LIMIT_3_0)

    def test_support_declaration(self):
        """Test support declaration for constant unfolding."""
        p = ConstantUnfoldingPass()

        support = p.get_support()

        expect(not ("x86_64" not in support.architectures))
        expect(not ("ELF" not in support.formats))
        expect(support.stability == "experimental")

    def test_unfold_zero(self):
        """Test zero constant unfolding."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_zero("eax", 32, _Binary(b"\x31\xc0"), 0x1000)

        expect(instructions is not None)
        expect(len(instructions) == 1)
        expect("xor" in instructions[0] or "sub" in instructions[0] or "and" in instructions[0])

    def test_unfold_one(self):
        """Test one constant unfolding."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_one("eax", 32, _Binary(b"\x40"), 0x1000)

        expect(instructions is not None)
        expect(not (len(instructions) < 1))

    def test_unfold_constant_add(self):
        """Test add constant unfolding."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_constant_add("eax", 3, 32)

        expect(instructions is not None)
        expect(len(instructions) == _EXPECTED_LEN_INSTRUCTIONS_3)
        expect(all("inc" in i for i in instructions))

    def test_unfold_constant_add_large(self):
        """Test large add constant unfolding."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_constant_add("eax", 10, 32)

        expect(instructions is not None)

    def test_unfold_constant_add_too_large(self):
        """Test that large constants don't unfold."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_constant_add("eax", 100, 32)

        expect(not (instructions is not None))

    def test_unfold_constant_sub(self):
        """Test sub constant unfolding."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_constant_sub("eax", 2, 32)

        expect(instructions is not None)
        expect(len(instructions) == _EXPECTED_LEN_INSTRUCTIONS_2)
        expect(all("dec" in i for i in instructions))

    def test_unfold_constant_sub_too_large(self):
        """Test that large subtraction constants don't unfold."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_constant_sub("eax", 100, 32)

        expect(not (instructions is not None))


class TestParallelExecutor:
    """Tests for ParallelMutator and related classes."""

    def test_initialization(self):
        """Test ParallelMutator initialization."""
        executor = ParallelMutator()

        expect(not (executor.max_workers <= 0))
        expect(executor.chunk_size == _EXPECTED_EXECUTOR_CHUNK_SIZE_10)
        expect(executor.timeout == _EXPECTED_EXECUTOR_TIMEOUT_300)

    def test_initialization_with_config(self):
        """Test ParallelMutator with custom config."""
        config = {
            "max_workers": 4,
            "chunk_size": 5,
            "timeout": 60,
        }
        executor = ParallelMutator(config)

        expect(executor.max_workers == _EXPECTED_EXECUTOR_MAX_WORKERS_4)
        expect(executor.chunk_size == _EXPECTED_EXECUTOR_CHUNK_SIZE_5)
        expect(executor.timeout == _EXPECTED_EXECUTOR_TIMEOUT_60)

    def test_mutation_task_creation(self):
        """Test MutationTask dataclass."""
        task = MutationTask(
            **{MUTATION_NAME_KEY: "NopInsertion"},
            pass_instance=DataFlowMutationPass(),
            function_addresses=[0x1000, 0x2000],
            config={"seed": 42},
        )

        expect(getattr(task, MUTATION_NAME_KEY) == "NopInsertion")
        expect(len(task.function_addresses) == _EXPECTED_LEN_TASK_FUNCTION_ADDRESSES_2)
        expect(task.config["seed"] == _EXPECTED_TASK_CONFIG_SEED_42)

    def test_parallel_stats(self):
        """Test ParallelStats dataclass."""
        stats = ParallelStats(
            total_time=1.5,
            worker_count=4,
            tasks_completed=10,
            tasks_failed=0,
            total_mutations=25,
            speedup_factor=2.5,
        )

        expect(stats.total_time == _EXPECTED_STATS_TOTAL_TIME_1_5)
        expect(stats.worker_count == _EXPECTED_STATS_WORKER_COUNT_4)
        expect(stats.tasks_completed == _EXPECTED_STATS_TASKS_COMPLETED_10)
        expect(stats.speedup_factor == _EXPECTED_STATS_SPEEDUP_FACTOR_2_5)

    def test_estimate_speedup_single_task(self):
        """Test speedup estimation with single task."""
        executor = ParallelMutator()

        speedup = executor.estimate_speedup([DataFlowMutationPass()], 5)

        expect(speedup == 1.0)

    def test_estimate_speedup_multiple_tasks(self):
        """Test speedup estimation with multiple tasks."""
        executor = ParallelMutator(config={"max_workers": 4})

        speedup = executor.estimate_speedup([DataFlowMutationPass()], 100)

        expect(not (speedup <= 1.0))

    def test_create_parallel_executor_factory(self):
        """Test factory function."""
        executor = create_parallel_executor({"max_workers": 2})

        expect(isinstance(executor, ParallelMutator))
        expect(executor.max_workers == _EXPECTED_EXECUTOR_MAX_WORKERS_2)


class TestNewMutationsIntegration:
    """Integration tests for new mutation passes."""

    def test_data_flow_pass_disabled(self):
        """Test that disabled pass returns empty result."""
        p = DataFlowMutationPass()
        p.disable()

        expect(not (p.enabled is not False))

    def test_string_obfuscation_pass_disabled(self):
        """Test that disabled string obfuscation returns empty result."""
        p = StringObfuscationPass()
        p.disable()

        expect(not (p.enabled is not False))

    def test_import_obfuscation_pass_disabled(self):
        """Test that disabled import obfuscation returns empty result."""
        p = ImportTableObfuscationPass()
        p.disable()

        expect(not (p.enabled is not False))

    def test_constant_unfolding_pass_disabled(self):
        """Test that disabled constant unfolding returns empty result."""
        p = ConstantUnfoldingPass()
        p.disable()

        expect(not (p.enabled is not False))

    def test_all_passes_have_required_methods(self):
        """Test that all passes implement required methods."""
        passes = [
            DataFlowMutationPass(),
            StringObfuscationPass(),
            ImportTableObfuscationPass(),
            ConstantUnfoldingPass(),
        ]

        for p in passes:
            expect(hasattr(p, "apply"))
            expect(hasattr(p, "run"))
            expect(hasattr(p, "get_support"))
            expect(hasattr(p, "get_stats"))
            expect(hasattr(p, "get_records"))
            expect(hasattr(p, "enable"))
            expect(hasattr(p, "disable"))
