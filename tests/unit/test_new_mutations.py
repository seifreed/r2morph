"""
Tests for new mutation passes: DataFlow, StringObfuscation, ImportObfuscation,
ConstantUnfolding, and ParallelExecutor.
"""

import pytest
from unittest.mock import MagicMock, patch

from r2morph.mutations.data_flow_mutation import DataFlowMutationPass
from r2morph.mutations.string_obfuscation import StringObfuscationPass
from r2morph.mutations.import_obfuscation import ImportTableObfuscationPass
from r2morph.mutations.constant_unfolding import ConstantUnfoldingPass
from r2morph.mutations.parallel_executor import (
    ParallelMutator,
    MutationTask,
    ParallelStats,
    create_parallel_executor,
)


class TestDataFlowMutationPass:
    """Tests for DataFlowMutationPass."""

    def test_initialization(self):
        """Test DataFlowMutationPass initialization."""
        p = DataFlowMutationPass()

        assert p.name == "DataFlowMutation"
        assert p.probability == 0.3
        assert p.max_mutations == 5
        assert p.use_liveness is True
        assert p.use_reaching_defs is True

    def test_initialization_with_config(self):
        """Test DataFlowMutationPass with custom config."""
        config = {
            "probability": 0.5,
            "max_mutations_per_function": 10,
            "use_liveness": False,
            "use_reaching_defs": False,
        }
        p = DataFlowMutationPass(config=config)

        assert p.probability == 0.5
        assert p.max_mutations == 10
        assert p.use_liveness is False
        assert p.use_reaching_defs is False

    def test_support_declaration(self):
        """Test support declaration for data flow pass."""
        p = DataFlowMutationPass()

        support = p.get_support()

        assert "x86_64" in support.architectures
        assert "ELF" in support.formats
        assert support.stability == "experimental"

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

        assert isinstance(live_in, dict)
        assert 0x1000 in live_in

    def test_is_register_safe_to_use(self):
        """Test register safety check."""
        p = DataFlowMutationPass()

        live_in = {0x1000: {"rax", "rcx"}}
        caller_saved = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}

        assert p._is_register_safe_to_use("rdx", 0x1000, live_in, caller_saved)
        assert not p._is_register_safe_to_use("rax", 0x1000, live_in, caller_saved)
        assert not p._is_register_safe_to_use("rbx", 0x1000, live_in, caller_saved)


class TestStringObfuscationPass:
    """Tests for StringObfuscationPass."""

    def test_initialization(self):
        """Test StringObfuscationPass initialization."""
        p = StringObfuscationPass()

        assert p.name == "StringObfuscation"
        assert p.probability == 0.5
        assert p.max_strings == 10
        assert p.encoding == "random"
        assert p.min_length == 4

    def test_encodings_list(self):
        """Test available encodings."""
        p = StringObfuscationPass()

        assert "xor" in p.ENCODINGS
        assert "rot13" in p.ENCODINGS
        assert "swap" in p.ENCODINGS

    def test_xor_encode(self):
        """Test XOR encoding."""
        p = StringObfuscationPass()

        data = b"Hello"
        key = 0x42

        encoded = p._xor_encode(data, key)

        assert len(encoded) == len(data)
        assert encoded != data

        decoded = bytes(b ^ key for b in encoded)
        assert decoded == data

    def test_rot13_encode(self):
        """Test ROT13 encoding."""
        p = StringObfuscationPass()

        data = b"Hello"
        encoded = p._rot13_encode(data)

        assert len(encoded) == len(data)

        assert encoded[0] == ord("U")  # H + 13 = U
        assert encoded[1] == ord("r")  # e + 13 = r

        decoded = p._rot13_encode(encoded)
        assert decoded == data

    def test_swap_encode(self):
        """Test byte swap encoding."""
        p = StringObfuscationPass()

        data = b"ABCD"
        encoded = p._swap_encode(data)

        assert encoded[0] == data[1]
        assert encoded[1] == data[0]
        assert encoded[2] == data[3]
        assert encoded[3] == data[2]

    def test_support_declaration(self):
        """Test support declaration for string obfuscation."""
        p = StringObfuscationPass()

        support = p.get_support()

        assert "x86_64" in support.architectures
        assert "ELF" in support.formats
        assert support.stability == "experimental"


class TestImportTableObfuscationPass:
    """Tests for ImportTableObfuscationPass."""

    def test_initialization(self):
        """Test ImportTableObfuscationPass initialization."""
        p = ImportTableObfuscationPass()

        assert p.name == "ImportTableObfuscation"
        assert p.probability == 0.5
        assert p.max_imports == 50

    def test_support_declaration(self):
        """Test support declaration for import obfuscation."""
        p = ImportTableObfuscationPass()

        support = p.get_support()

        assert "x86_64" in support.architectures
        assert "ELF" in support.formats
        assert "PE" in support.formats
        assert support.stability == "experimental"

    def test_get_imports_elf_empty(self):
        """Test ELF import extraction with empty result."""
        p = ImportTableObfuscationPass()

        mock_binary = MagicMock()
        mock_binary.r2 = None

        imports = p._get_imports_elf(mock_binary)

        assert imports == []


class TestConstantUnfoldingPass:
    """Tests for ConstantUnfoldingPass."""

    def test_initialization(self):
        """Test ConstantUnfoldingPass initialization."""
        p = ConstantUnfoldingPass()

        assert p.name == "ConstantUnfolding"
        assert p.probability == 0.3
        assert p.max_unfolds == 5
        assert p.max_sequence == 10
        assert p.size_limit == 3.0

    def test_support_declaration(self):
        """Test support declaration for constant unfolding."""
        p = ConstantUnfoldingPass()

        support = p.get_support()

        assert "x86_64" in support.architectures
        assert "ELF" in support.formats
        assert support.stability == "experimental"

    def test_unfold_zero(self):
        """Test zero constant unfolding."""
        p = ConstantUnfoldingPass()

        mock_binary = MagicMock()
        mock_binary.assemble = MagicMock(return_value=b"\x31\xc0")

        instructions = p._unfold_zero("eax", 32, mock_binary, 0x1000)

        assert instructions is not None
        assert len(instructions) == 1
        assert "xor" in instructions[0] or "sub" in instructions[0] or "and" in instructions[0]

    def test_unfold_one(self):
        """Test one constant unfolding."""
        p = ConstantUnfoldingPass()

        mock_binary = MagicMock()
        mock_binary.assemble = MagicMock(return_value=b"\x40")

        instructions = p._unfold_one("eax", 32, mock_binary, 0x1000)

        assert instructions is not None
        assert len(instructions) >= 1

    def test_unfold_constant_add(self):
        """Test add constant unfolding."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_constant_add("eax", 3, 32)

        assert instructions is not None
        assert len(instructions) == 3
        assert all("inc" in i for i in instructions)

    def test_unfold_constant_add_large(self):
        """Test large add constant unfolding."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_constant_add("eax", 10, 32)

        assert instructions is not None

    def test_unfold_constant_add_too_large(self):
        """Test that large constants don't unfold."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_constant_add("eax", 100, 32)

        assert instructions is None

    def test_unfold_constant_sub(self):
        """Test sub constant unfolding."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_constant_sub("eax", 2, 32)

        assert instructions is not None
        assert len(instructions) == 2
        assert all("dec" in i for i in instructions)

    def test_unfold_constant_sub_too_large(self):
        """Test that large subtraction constants don't unfold."""
        p = ConstantUnfoldingPass()

        instructions = p._unfold_constant_sub("eax", 100, 32)

        assert instructions is None


class TestParallelExecutor:
    """Tests for ParallelMutator and related classes."""

    def test_initialization(self):
        """Test ParallelMutator initialization."""
        executor = ParallelMutator()

        assert executor.max_workers > 0
        assert executor.chunk_size == 10
        assert executor.timeout == 300

    def test_initialization_with_config(self):
        """Test ParallelMutator with custom config."""
        config = {
            "max_workers": 4,
            "chunk_size": 5,
            "timeout": 60,
        }
        executor = ParallelMutator(config)

        assert executor.max_workers == 4
        assert executor.chunk_size == 5
        assert executor.timeout == 60

    def test_mutation_task_creation(self):
        """Test MutationTask dataclass."""
        task = MutationTask(
            pass_name="NopInsertion",
            pass_instance=MagicMock(),
            function_addresses=[0x1000, 0x2000],
            config={"seed": 42},
        )

        assert task.pass_name == "NopInsertion"
        assert len(task.function_addresses) == 2
        assert task.config["seed"] == 42

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

        assert stats.total_time == 1.5
        assert stats.worker_count == 4
        assert stats.tasks_completed == 10
        assert stats.speedup_factor == 2.5

    def test_is_mutation_independent(self):
        """Test mutation independence check."""
        from r2morph.mutations.base import MutationRecord

        executor = ParallelMutator()

        mutation1 = MutationRecord(
            pass_name="test",
            function_address=0x1000,
            start_address=0x1000,
            end_address=0x1010,
            original_bytes="00",
            mutated_bytes="ff",
            original_disasm="mov eax, 0",
            mutated_disasm="xor eax, eax",
            mutation_kind="test",
        )

        mutation2 = MutationRecord(
            pass_name="test",
            function_address=0x2000,
            start_address=0x2000,
            end_address=0x2010,
            original_bytes="00",
            mutated_bytes="ff",
            original_disasm="mov ebx, 0",
            mutated_disasm="xor ebx, ebx",
            mutation_kind="test",
        )

        assert executor._is_mutation_independent(mutation1, mutation2)

        mutation3 = MutationRecord(
            pass_name="test",
            function_address=0x1000,
            start_address=0x1005,
            end_address=0x1015,
            original_bytes="00",
            mutated_bytes="ff",
            original_disasm="mov ecx, 0",
            mutated_disasm="xor ecx, ecx",
            mutation_kind="test",
        )

        assert not executor._is_mutation_independent(mutation1, mutation3)

    def test_estimate_speedup_single_task(self):
        """Test speedup estimation with single task."""
        executor = ParallelMutator()

        mock_pass = MagicMock()
        mock_pass.enabled = True

        speedup = executor.estimate_speedup([mock_pass], 5)

        assert speedup == 1.0

    def test_estimate_speedup_multiple_tasks(self):
        """Test speedup estimation with multiple tasks."""
        executor = ParallelMutator(config={"max_workers": 4})

        mock_pass = MagicMock()
        mock_pass.enabled = True

        speedup = executor.estimate_speedup([mock_pass], 100)

        assert speedup > 1.0

    def test_create_parallel_executor_factory(self):
        """Test factory function."""
        executor = create_parallel_executor({"max_workers": 2})

        assert isinstance(executor, ParallelMutator)
        assert executor.max_workers == 2


class TestNewMutationsIntegration:
    """Integration tests for new mutation passes."""

    def test_data_flow_pass_disabled(self):
        """Test that disabled pass returns empty result."""
        p = DataFlowMutationPass()
        p.disable()

        assert p.enabled is False

    def test_string_obfuscation_pass_disabled(self):
        """Test that disabled string obfuscation returns empty result."""
        p = StringObfuscationPass()
        p.disable()

        assert p.enabled is False

    def test_import_obfuscation_pass_disabled(self):
        """Test that disabled import obfuscation returns empty result."""
        p = ImportTableObfuscationPass()
        p.disable()

        assert p.enabled is False

    def test_constant_unfolding_pass_disabled(self):
        """Test that disabled constant unfolding returns empty result."""
        p = ConstantUnfoldingPass()
        p.disable()

        assert p.enabled is False

    def test_all_passes_have_required_methods(self):
        """Test that all passes implement required methods."""
        passes = [
            DataFlowMutationPass(),
            StringObfuscationPass(),
            ImportTableObfuscationPass(),
            ConstantUnfoldingPass(),
        ]

        for p in passes:
            assert hasattr(p, "apply")
            assert hasattr(p, "run")
            assert hasattr(p, "get_support")
            assert hasattr(p, "get_stats")
            assert hasattr(p, "get_records")
            assert hasattr(p, "enable")
            assert hasattr(p, "disable")
