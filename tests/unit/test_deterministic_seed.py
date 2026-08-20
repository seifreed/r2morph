"""
Tests for deterministic mutation runs with seed control.

Tests for Issue #6:
- Same seed produces identical outputs
- Different seeds produce different outputs
- Seed is included in mutation records
- All passes support seed control
"""

import pytest

import r2morph.core.randomness as random
from r2morph.mutations.base import MutationPass, MutationRecord, MutationResult
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY

_EXPECTED_D_SEED_12345 = 12345
_EXPECTED_D_SEED_12345_2 = 12345
_EXPECTED_P_CONFIG_GET_CONFIG_KEY_42 = 42
_EXPECTED_P_CONFIG_GET_SEED_42 = 42
_EXPECTED_P_CONFIG_GET_SEED_42_2 = 42
_EXPECTED_P_CONFIG_GET_SEED_42_3 = 42
_EXPECTED_RECORD_METADATA_SEED_12345 = 12345
_EXPECTED_RECORD_SEED_12345 = 12345
_EXPECTED_RESULT_1005 = 1005
_EXPECTED_RESULT_12345 = 12345
_EXPECTED_RESULT_12345_2 = 12345
_EXPECTED_RESULT_12345_3 = 12345
_EXPECTED_RESULT_METADATA_SEED_12345 = 12345
_EXPECTED_RESULT_SEED_99999 = 99999
_EXPECTED_SEED1_100 = 100
_EXPECTED_SEED1_1001 = 1001
_EXPECTED_SEED1_42 = 42
_EXPECTED_SEED2_1002 = 1002
_EXPECTED_SEED2_200 = 200
_EXPECTED_SEED2_99 = 99
_EXPECTED_SEED_42 = 42


class MockBinary:
    """Mock binary for testing."""

    def __init__(self):
        self._analyzed = False
        self._functions = []
        self._arch_info = {"arch": "x86_64", "bits": 64}

    def is_analyzed(self):
        return self._analyzed

    def analyze(self):
        self._analyzed = True

    def get_functions(self):
        return self._functions

    def get_arch_info(self):
        return self._arch_info

    def get_function_disasm(self, addr):
        return []


class TestSeedControl:
    """Tests for seed control in mutation passes."""

    def test_reset_random_no_seed(self):
        """Test _reset_random without seed."""

        class TestPass(MutationPass):
            def apply(self, binary):
                return {"mutations_applied": 0}

        p = TestPass("test", config={})
        result = p._reset_random()

        expect(not (result is not None))

    def test_reset_random_with_seed(self):
        """Test _reset_random with explicit seed."""

        class TestPass(MutationPass):
            def apply(self, binary):
                return {"mutations_applied": 0}

        p = TestPass("test", config={"seed": 12345})
        result = p._reset_random()

        expect(result == _EXPECTED_RESULT_12345)

    def test_reset_random_derived_seed(self):
        """Test _reset_random with derived seed."""

        class TestPass(MutationPass):
            def apply(self, binary):
                return {"mutations_applied": 0}

        p = TestPass("test", config={"seed": 1000, "_pass_seed": 1005, "_use_derived_seed": True})
        result = p._reset_random()

        expect(result == _EXPECTED_RESULT_1005)

    def test_derived_seed_different_per_pass(self):
        """Test that derived seeds are different per pass."""

        class TestPass(MutationPass):
            def apply(self, binary):
                return {"mutations_applied": 0}

        pass1 = TestPass("test1", config={"seed": 1000, "_pass_seed": 1001, "_use_derived_seed": True})
        pass2 = TestPass("test2", config={"seed": 1000, "_pass_seed": 1002, "_use_derived_seed": True})

        seed1 = pass1._reset_random()
        seed2 = pass2._reset_random()

        expect(seed1 == _EXPECTED_SEED1_1001)
        expect(seed2 == _EXPECTED_SEED2_1002)
        expect(seed1 != seed2)


class TestDeterministicRandom:
    """Tests for deterministic random behavior."""

    def test_same_seed_same_random_sequence(self):
        """Test that same seed produces same random sequence."""
        random.seed(42)
        seq1 = [random.random() for _ in range(10)]

        random.seed(42)
        seq2 = [random.random() for _ in range(10)]

        expect(seq1 == seq2)

    def test_different_seed_different_random_sequence(self):
        """Test that different seeds produce different sequences."""
        random.seed(42)
        seq1 = [random.random() for _ in range(10)]

        random.seed(99)
        seq2 = [random.random() for _ in range(10)]

        expect(seq1 != seq2)

    def test_random_shuffle_deterministic(self):
        """Test that random.shuffle is deterministic with seed."""
        items1 = list(range(10))
        items2 = list(range(10))

        random.seed(42)
        random.shuffle(items1)

        random.seed(42)
        random.shuffle(items2)

        expect(items1 == items2)

    def test_random_choice_deterministic(self):
        """Test that random.choice is deterministic with seed."""
        items = ["a", "b", "c", "d", "e"]

        random.seed(42)
        choices1 = [random.choice(items) for _ in range(10)]

        random.seed(42)
        choices2 = [random.choice(items) for _ in range(10)]

        expect(choices1 == choices2)

    def test_random_sample_deterministic(self):
        """Test that random.sample is deterministic with seed."""
        items = list(range(20))

        random.seed(42)
        sample1 = random.sample(items, 5)

        random.seed(42)
        sample2 = random.sample(items, 5)

        expect(sample1 == sample2)


class TestMutationRecordSeed:
    """Tests for seed in mutation records."""

    def test_mutation_record_with_seed(self):
        """Test creating mutation record with seed."""
        record = MutationRecord(
            **{MUTATION_NAME_KEY: "test"},
            function_address=0x1000,
            start_address=0x1000,
            end_address=0x1010,
            original_bytes="90909090",
            mutated_bytes="b800000000",
            original_disasm="nop",
            mutated_disasm="mov eax, 0",
            mutation_kind="test",
            seed=12345,
        )

        expect(record.seed == _EXPECTED_RECORD_SEED_12345)

    def test_mutation_record_without_seed(self):
        """Test creating mutation record without seed."""
        record = MutationRecord(
            **{MUTATION_NAME_KEY: "test"},
            function_address=0x1000,
            start_address=0x1000,
            end_address=0x1010,
            original_bytes="90909090",
            mutated_bytes="b800000000",
            original_disasm="nop",
            mutated_disasm="mov eax, 0",
            mutation_kind="test",
        )

        expect(not (record.seed is not None))

    def test_mutation_record_to_dict_includes_seed(self):
        """Test that to_dict includes seed."""
        record = MutationRecord(
            **{MUTATION_NAME_KEY: "test"},
            function_address=0x1000,
            start_address=0x1000,
            end_address=0x1010,
            original_bytes="90909090",
            mutated_bytes="b800000000",
            original_disasm="nop",
            mutated_disasm="mov eax, 0",
            mutation_kind="test",
            seed=12345,
        )

        d = record.to_dict()

        expect(not ("seed" not in d))
        expect(d["seed"] == _EXPECTED_D_SEED_12345)


class TestMutationResultSeed:
    """Tests for seed in mutation results."""

    def test_mutation_result_with_seed(self):
        """Test creating mutation result with seed."""
        result = MutationResult(
            success=True,
            mutations_applied=5,
            seed=99999,
        )

        expect(result.seed == _EXPECTED_RESULT_SEED_99999)

    def test_mutation_result_without_seed(self):
        """Test creating mutation result without seed."""
        result = MutationResult(
            success=True,
            mutations_applied=5,
        )

        expect(not (result.seed is not None))

    def test_mutation_result_to_dict_includes_seed(self):
        """Test that to_dict includes seed."""
        result = MutationResult(
            success=True,
            mutations_applied=5,
            seed=12345,
        )

        d = result.to_dict()

        expect(not ("seed" not in d))
        expect(d["seed"] == _EXPECTED_D_SEED_12345_2)


class TestPassSeedIntegration:
    """Tests for seed integration in passes."""

    def test_nop_insertion_pass_seed_config(self):
        """Test NopInsertionPass accepts seed config."""
        config = {"seed": 42, "probability": 0.5}
        p = NopInsertionPass(config=config)

        expect(p.config.get("seed") == _EXPECTED_P_CONFIG_GET_SEED_42)

    def test_instruction_substitution_pass_seed_config(self):
        """Test InstructionSubstitutionPass accepts seed config."""
        config = {"seed": 42, "probability": 0.5}
        p = InstructionSubstitutionPass(config=config)

        expect(p.config.get("seed") == _EXPECTED_P_CONFIG_GET_SEED_42_2)

    def test_register_substitution_pass_seed_config(self):
        """Test RegisterSubstitutionPass accepts seed config."""
        config = {"seed": 42, "probability": 0.5}
        p = RegisterSubstitutionPass(config=config)

        expect(p.config.get("seed") == _EXPECTED_P_CONFIG_GET_SEED_42_3)


class TestDeterministicSequences:
    """Tests that verify deterministic sequences."""

    def test_reset_random_sequence(self):
        """Test that _reset_random produces same sequence."""

        class TestPass(MutationPass):
            def apply(self, binary):
                return {"mutations_applied": 0}

        p1 = TestPass("test1", config={"seed": 12345})
        p2 = TestPass("test2", config={"seed": 12345})

        p1._reset_random()
        seq1 = [random.random() for _ in range(5)]

        p2._reset_random()
        seq2 = [random.random() for _ in range(5)]

        expect(seq1 == seq2)

    def test_different_seeds_different_sequences(self):
        """Test that different seeds produce different sequences."""

        class TestPass(MutationPass):
            def apply(self, binary):
                return {"mutations_applied": 0}

        p1 = TestPass("test1", config={"seed": 12345})
        p2 = TestPass("test2", config={"seed": 54321})

        p1._reset_random()
        seq1 = [random.random() for _ in range(5)]

        p2._reset_random()
        seq2 = [random.random() for _ in range(5)]

        expect(seq1 != seq2)


class TestSeedInReport:
    """Tests for seed inclusion in reports."""

    def test_result_metadata_can_contain_seed(self):
        """Test that result metadata can contain seed."""
        result = MutationResult(
            success=True,
            mutations_applied=5,
            metadata={"seed": 12345, "pass": "test"},
        )

        expect(result.metadata["seed"] == _EXPECTED_RESULT_METADATA_SEED_12345)

    def test_record_metadata_can_contain_seed(self):
        """Test that record metadata can contain seed."""
        record = MutationRecord(
            **{MUTATION_NAME_KEY: "test"},
            function_address=0x1000,
            start_address=0x1000,
            end_address=0x1010,
            original_bytes="9090",
            mutated_bytes="b800",
            original_disasm="nop",
            mutated_disasm="mov",
            mutation_kind="test",
            metadata={"seed": 12345},
        )

        expect(record.metadata["seed"] == _EXPECTED_RECORD_METADATA_SEED_12345)


class TestConsecutiveRunsDeterminism:
    """Tests that verify deterministic output across consecutive runs."""

    def test_same_seed_same_random_after_reset(self):
        """Test that resetting with same seed produces same random."""
        random.seed(42)
        values1 = [random.randint(0, 100) for _ in range(20)]

        random.seed(42)
        values2 = [random.randint(0, 100) for _ in range(20)]

        expect(values1 == values2)

    def test_random_state_isolated_between_passes(self):
        """Test that random state is isolated between passes."""

        class TestPass(MutationPass):
            def apply(self, binary):
                return {"mutations_applied": 0}

        p1 = TestPass("pass1", config={"_pass_seed": 100, "_use_derived_seed": True})
        p2 = TestPass("pass2", config={"_pass_seed": 200, "_use_derived_seed": True})

        seed1 = p1._reset_random()
        values1 = [random.randint(0, 100) for _ in range(5)]

        seed2 = p2._reset_random()
        values2 = [random.randint(0, 100) for _ in range(5)]

        expect(seed1 == _EXPECTED_SEED1_100)
        expect(seed2 == _EXPECTED_SEED2_200)
        expect(values1 != values2)


class TestSeedDocumentation:
    """Tests verifying seed documentation behavior."""

    def test_seed_is_int(self):
        """Test that seed is converted to int."""

        class TestPass(MutationPass):
            def apply(self, binary):
                return {"mutations_applied": 0}

        p = TestPass("test", config={"seed": "12345"})
        result = p._reset_random()

        expect(result == _EXPECTED_RESULT_12345_2)
        expect(isinstance(result, int))

    def test_pass_seed_is_int(self):
        """Test that _pass_seed is used as int."""

        class TestPass(MutationPass):
            def apply(self, binary):
                return {"mutations_applied": 0}

        p = TestPass("test", config={"_pass_seed": "12345", "_use_derived_seed": True})
        result = p._reset_random()

        expect(result == _EXPECTED_RESULT_12345_3)


@pytest.mark.parametrize(
    "pass_class,config_key",
    [
        (NopInsertionPass, "seed"),
        (InstructionSubstitutionPass, "seed"),
        (RegisterSubstitutionPass, "seed"),
    ],
)
class TestPassSeedControl:
    """Parametrized tests for pass seed control."""

    def test_pass_accepts_seed(self, pass_class, config_key):
        """Test that pass accepts seed configuration."""
        config = {config_key: 42}
        p = pass_class(config=config)
        expect(p.config.get(config_key) == _EXPECTED_P_CONFIG_GET_CONFIG_KEY_42)

    def test_pass_reset_random_with_seed(self, pass_class, config_key):
        """Test that pass resets random with seed."""
        config = {config_key: 42}
        p = pass_class(config=config)

        seed = p._reset_random()

        expect(seed == _EXPECTED_SEED_42)

    def test_pass_different_seeds_different_results(self, pass_class, config_key):
        """Test that different seeds produce different results."""
        p1 = pass_class(config={config_key: 42})
        p2 = pass_class(config={config_key: 99})

        seed1 = p1._reset_random()
        seed2 = p2._reset_random()

        expect(seed1 == _EXPECTED_SEED1_42)
        expect(seed2 == _EXPECTED_SEED2_99)
        expect(seed1 != seed2)
