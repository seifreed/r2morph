"""
Unit tests for configuration dataclasses.
"""

import importlib.util

import pytest

from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)

from r2morph.core.config import (
    AnalysisConfig,
    EngineConfig,
    InstructionSubstitutionConfig,
    MutationConfig,
    NopInsertionConfig,
    RegisterSubstitutionConfig,
)

_EXPECTED_CONFIG_ANALYSIS_TIMEOUT_SECONDS_600 = 600
_EXPECTED_CONFIG_BLOCK_MAX_PER_FUNCTION_8 = 8
_EXPECTED_CONFIG_BLOCK_MAX_REORDERINGS_PER_FUNCTION_8 = 8
_EXPECTED_CONFIG_BLOCK_PROBABILITY_0_8 = 0.8
_EXPECTED_CONFIG_EXPANSION_MAX_EXPANSIONS_PER_FUNCTION_15 = 15
_EXPECTED_CONFIG_EXPANSION_MAX_PER_FUNCTION_15 = 15
_EXPECTED_CONFIG_EXPANSION_PROBABILITY_0_9 = 0.9
_EXPECTED_CONFIG_MAX_NOPS_PER_FUNCTION_12 = 12
_EXPECTED_CONFIG_MAX_NOPS_PER_FUNCTION_5 = 5
_EXPECTED_CONFIG_MAX_PER_FUNCTION_10 = 10
_EXPECTED_CONFIG_MAX_PER_FUNCTION_20 = 20
_EXPECTED_CONFIG_MAX_PER_FUNCTION_5 = 5
_EXPECTED_CONFIG_MAX_PER_FUNCTION_8 = 8
_EXPECTED_CONFIG_MAX_SUBSTITUTIONS_PER_FUNCTION_10 = 10
_EXPECTED_CONFIG_MAX_SUBSTITUTIONS_PER_FUNCTION_5 = 5
_EXPECTED_CONFIG_NOP_MAX_NOPS_PER_FUNCTION_20 = 20
_EXPECTED_CONFIG_NOP_MAX_PER_FUNCTION_15 = 15
_EXPECTED_CONFIG_NOP_MAX_PER_FUNCTION_2 = 2
_EXPECTED_CONFIG_NOP_MAX_PER_FUNCTION_20 = 20
_EXPECTED_CONFIG_NOP_MAX_PER_FUNCTION_5 = 5
_EXPECTED_CONFIG_NOP_PROBABILITY_0_3 = 0.3
_EXPECTED_CONFIG_NOP_PROBABILITY_0_5 = 0.5
_EXPECTED_CONFIG_NOP_PROBABILITY_0_95 = 0.95
_EXPECTED_CONFIG_PROBABILITY_0_5 = 0.5
_EXPECTED_CONFIG_PROBABILITY_0_7 = 0.7
_EXPECTED_CONFIG_PROBABILITY_0_8 = 0.8
_EXPECTED_CONFIG_REGISTER_MAX_PER_FUNCTION_15 = 15
_EXPECTED_CONFIG_REGISTER_MAX_SUBSTITUTIONS_PER_FUNCTIO_15 = 15
_EXPECTED_CONFIG_REGISTER_MAX_SUBSTITUTIONS_PER_FUNCTIO_2 = 2
_EXPECTED_CONFIG_REGISTER_PROBABILITY_0_9 = 0.9
_EXPECTED_CONFIG_SUBSTITUTION_MAX_PER_FUNCTION_2 = 2
_EXPECTED_CONFIG_SUBSTITUTION_MAX_PER_FUNCTION_30 = 30
_EXPECTED_CONFIG_SUBSTITUTION_MAX_SUBSTITUTIONS_PER_FUN_10 = 10
_EXPECTED_CONFIG_SUBSTITUTION_MAX_SUBSTITUTIONS_PER_FUN_30 = 30
_EXPECTED_CONFIG_SUBSTITUTION_PROBABILITY_0_95 = 0.95
_EXPECTED_CONFIG_TIMEOUT_SECONDS_300 = 300
_EXPECTED_CONFIG_TIMEOUT_SECONDS_600 = 600
_EXPECTED_RESULT_MAX_NOPS_PER_FUNCTION_7 = 7
_EXPECTED_RESULT_MAX_PER_FUNCTION_3 = 3
_EXPECTED_RESULT_MAX_PER_FUNCTION_7 = 7
_EXPECTED_RESULT_MAX_SUBSTITUTIONS_PER_FUNCTION_15 = 15
_EXPECTED_RESULT_MAX_SUBSTITUTIONS_PER_FUNCTION_8 = 8
_EXPECTED_RESULT_NOP_MAX_PER_FUNCTION_20 = 20
_EXPECTED_RESULT_PROBABILITY_0_6 = 0.6
_EXPECTED_RESULT_SUBSTITUTION_MAX_SUBSTITUTIONS_PER_FUN_30 = 30
_EXPECTED_RESULT_TIMEOUT_SECONDS_120 = 120


class TestMutationConfig:
    """Tests for MutationConfig base dataclass."""

    def test_mutation_config_defaults(self):
        """Test MutationConfig default values."""
        config = MutationConfig()
        expect(config.max_per_function == _EXPECTED_CONFIG_MAX_PER_FUNCTION_5)
        expect(config.probability == _EXPECTED_CONFIG_PROBABILITY_0_5)
        expect(not (config.force_different))

    def test_mutation_config_custom_values(self):
        """Test MutationConfig with custom values."""
        config = MutationConfig(max_per_function=10, probability=0.8, force_different=True)
        expect(config.max_per_function == _EXPECTED_CONFIG_MAX_PER_FUNCTION_10)
        expect(config.probability == _EXPECTED_CONFIG_PROBABILITY_0_8)
        expect(config.force_different)

    def test_mutation_config_to_dict(self):
        """Test MutationConfig to_dict() method."""
        config = MutationConfig(max_per_function=7, probability=0.6, force_different=True)
        result = config.to_dict()

        expect(isinstance(result, dict))
        expect(result["max_per_function"] == _EXPECTED_RESULT_MAX_PER_FUNCTION_7)
        expect(result["probability"] == _EXPECTED_RESULT_PROBABILITY_0_6)
        expect(result["force_different"])


class TestNopInsertionConfig:
    """Tests for NopInsertionConfig dataclass."""

    def test_nop_insertion_config_defaults(self):
        """Test NopInsertionConfig default values."""
        config = NopInsertionConfig()
        # Inherited defaults
        expect(config.max_per_function == _EXPECTED_CONFIG_MAX_PER_FUNCTION_5)
        expect(config.probability == _EXPECTED_CONFIG_PROBABILITY_0_5)
        expect(not (config.force_different))
        # Own defaults
        expect(config.use_creative_nops)
        expect(config.max_nops_per_function == _EXPECTED_CONFIG_MAX_NOPS_PER_FUNCTION_5)

    def test_nop_insertion_config_custom_values(self):
        """Test NopInsertionConfig with custom values."""
        config = NopInsertionConfig(
            max_per_function=8, probability=0.7, force_different=True, use_creative_nops=False, max_nops_per_function=12
        )
        expect(config.max_per_function == _EXPECTED_CONFIG_MAX_PER_FUNCTION_8)
        expect(config.probability == _EXPECTED_CONFIG_PROBABILITY_0_7)
        expect(config.force_different)
        expect(not (config.use_creative_nops))
        expect(config.max_nops_per_function == _EXPECTED_CONFIG_MAX_NOPS_PER_FUNCTION_12)

    def test_nop_insertion_config_to_dict(self):
        """Test NopInsertionConfig to_dict() includes all fields."""
        config = NopInsertionConfig(max_per_function=3, use_creative_nops=False, max_nops_per_function=7)
        result = config.to_dict()

        expect(isinstance(result, dict))
        # Base fields
        expect(not ("max_per_function" not in result))
        expect(result["max_per_function"] == _EXPECTED_RESULT_MAX_PER_FUNCTION_3)
        # NOP-specific fields
        expect(not ("use_creative_nops" not in result))
        expect(not (result["use_creative_nops"]))
        expect(not ("max_nops_per_function" not in result))
        expect(result["max_nops_per_function"] == _EXPECTED_RESULT_MAX_NOPS_PER_FUNCTION_7)


class TestInstructionSubstitutionConfig:
    """Tests for InstructionSubstitutionConfig dataclass."""

    def test_instruction_substitution_config_defaults(self):
        """Test InstructionSubstitutionConfig default values."""
        config = InstructionSubstitutionConfig()
        expect(config.max_per_function == _EXPECTED_CONFIG_MAX_PER_FUNCTION_5)
        expect(config.probability == _EXPECTED_CONFIG_PROBABILITY_0_5)
        expect(config.max_substitutions_per_function == _EXPECTED_CONFIG_MAX_SUBSTITUTIONS_PER_FUNCTION_10)

    def test_instruction_substitution_config_to_dict(self):
        """Test InstructionSubstitutionConfig to_dict() method."""
        config = InstructionSubstitutionConfig(max_substitutions_per_function=15)
        result = config.to_dict()

        expect(not ("max_substitutions_per_function" not in result))
        expect(result["max_substitutions_per_function"] == _EXPECTED_RESULT_MAX_SUBSTITUTIONS_PER_FUNCTION_15)


class TestRegisterSubstitutionConfig:
    """Tests for RegisterSubstitutionConfig dataclass."""

    def test_register_substitution_config_defaults(self):
        """Test RegisterSubstitutionConfig default values."""
        config = RegisterSubstitutionConfig()
        expect(config.max_per_function == _EXPECTED_CONFIG_MAX_PER_FUNCTION_5)
        expect(config.probability == _EXPECTED_CONFIG_PROBABILITY_0_5)
        expect(config.max_substitutions_per_function == _EXPECTED_CONFIG_MAX_SUBSTITUTIONS_PER_FUNCTION_5)

    def test_register_substitution_config_to_dict(self):
        """Test RegisterSubstitutionConfig to_dict() method."""
        config = RegisterSubstitutionConfig(max_substitutions_per_function=8)
        result = config.to_dict()

        expect(not ("max_substitutions_per_function" not in result))
        expect(result["max_substitutions_per_function"] == _EXPECTED_RESULT_MAX_SUBSTITUTIONS_PER_FUNCTION_8)


class TestAnalysisConfig:
    """Tests for AnalysisConfig dataclass."""

    def test_analysis_config_defaults(self):
        """Test AnalysisConfig default values."""
        config = AnalysisConfig()
        expect(config.level == "auto")
        expect(config.timeout_seconds == _EXPECTED_CONFIG_TIMEOUT_SECONDS_300)
        expect(not (config.low_memory))

    def test_analysis_config_custom_values(self):
        """Test AnalysisConfig with custom values."""
        config = AnalysisConfig(level="aaa", timeout_seconds=600, low_memory=True)
        expect(config.level == "aaa")
        expect(config.timeout_seconds == _EXPECTED_CONFIG_TIMEOUT_SECONDS_600)
        expect(config.low_memory)

    def test_analysis_config_to_dict(self):
        """Test AnalysisConfig to_dict() method."""
        config = AnalysisConfig(level="aa", timeout_seconds=120, low_memory=True)
        result = config.to_dict()

        expect(result["level"] == "aa")
        expect(result["timeout_seconds"] == _EXPECTED_RESULT_TIMEOUT_SECONDS_120)
        expect(result["low_memory"])


class TestEngineConfig:
    """Tests for EngineConfig main configuration."""

    def test_engine_config_defaults(self):
        """Test EngineConfig default values."""
        config = EngineConfig()
        expect(not (config.aggressive))
        expect(not (config.force_different))
        expect(isinstance(config.nop, NopInsertionConfig))
        expect(isinstance(config.substitution, InstructionSubstitutionConfig))
        expect(isinstance(config.register, RegisterSubstitutionConfig))
        expect(isinstance(config.analysis, AnalysisConfig))

    def test_engine_config_factory_default(self):
        """Test EngineConfig.create_default() factory method."""
        config = EngineConfig.create_default()

        expect(not (config.aggressive))
        expect(not (config.force_different))
        expect(config.nop.max_per_function == _EXPECTED_CONFIG_NOP_MAX_PER_FUNCTION_5)
        expect(config.nop.probability == _EXPECTED_CONFIG_NOP_PROBABILITY_0_5)
        expect(config.nop.use_creative_nops)
        expect(
            config.substitution.max_substitutions_per_function
            == _EXPECTED_CONFIG_SUBSTITUTION_MAX_SUBSTITUTIONS_PER_FUN_10
        )
        expect(config.analysis.level == "auto")
        expect(not (config.analysis.low_memory))

    def test_engine_config_factory_aggressive(self):
        """Test EngineConfig.create_aggressive() factory method."""
        config = EngineConfig.create_aggressive()

        expect(config.aggressive)
        expect(config.force_different)
        expect(config.nop.max_per_function == _EXPECTED_CONFIG_NOP_MAX_PER_FUNCTION_20)
        expect(config.nop.probability == _EXPECTED_CONFIG_NOP_PROBABILITY_0_95)
        expect(config.nop.force_different)
        expect(config.nop.max_nops_per_function == _EXPECTED_CONFIG_NOP_MAX_NOPS_PER_FUNCTION_20)
        expect(config.nop.use_creative_nops)
        expect(config.substitution.max_per_function == _EXPECTED_CONFIG_SUBSTITUTION_MAX_PER_FUNCTION_30)
        expect(config.substitution.probability == _EXPECTED_CONFIG_SUBSTITUTION_PROBABILITY_0_95)
        expect(
            config.substitution.max_substitutions_per_function
            == _EXPECTED_CONFIG_SUBSTITUTION_MAX_SUBSTITUTIONS_PER_FUN_30
        )
        expect(config.substitution.force_different)
        expect(config.register.max_per_function == _EXPECTED_CONFIG_REGISTER_MAX_PER_FUNCTION_15)
        expect(config.register.probability == _EXPECTED_CONFIG_REGISTER_PROBABILITY_0_9)
        expect(
            config.register.max_substitutions_per_function == _EXPECTED_CONFIG_REGISTER_MAX_SUBSTITUTIONS_PER_FUNCTIO_15
        )
        expect(config.register.force_different)
        expect(config.expansion.max_per_function == _EXPECTED_CONFIG_EXPANSION_MAX_PER_FUNCTION_15)
        expect(config.expansion.probability == _EXPECTED_CONFIG_EXPANSION_PROBABILITY_0_9)
        expect(
            config.expansion.max_expansions_per_function == _EXPECTED_CONFIG_EXPANSION_MAX_EXPANSIONS_PER_FUNCTION_15
        )
        expect(config.expansion.force_different)
        expect(config.block.max_per_function == _EXPECTED_CONFIG_BLOCK_MAX_PER_FUNCTION_8)
        expect(config.block.probability == _EXPECTED_CONFIG_BLOCK_PROBABILITY_0_8)
        expect(config.block.max_reorderings_per_function == _EXPECTED_CONFIG_BLOCK_MAX_REORDERINGS_PER_FUNCTION_8)
        expect(config.block.force_different)
        expect(config.analysis.level == "aaa")
        expect(config.analysis.timeout_seconds == _EXPECTED_CONFIG_ANALYSIS_TIMEOUT_SECONDS_600)

    def test_engine_config_factory_memory_efficient(self):
        """Test EngineConfig.create_memory_efficient() factory method."""
        config = EngineConfig.create_memory_efficient()

        expect(not (config.aggressive))
        expect(not (config.force_different))
        expect(config.nop.max_per_function == _EXPECTED_CONFIG_NOP_MAX_PER_FUNCTION_2)
        expect(config.nop.probability == _EXPECTED_CONFIG_NOP_PROBABILITY_0_3)
        expect(not (config.nop.use_creative_nops))
        expect(config.substitution.max_per_function == _EXPECTED_CONFIG_SUBSTITUTION_MAX_PER_FUNCTION_2)
        expect(
            config.register.max_substitutions_per_function == _EXPECTED_CONFIG_REGISTER_MAX_SUBSTITUTIONS_PER_FUNCTIO_2
        )
        expect(config.analysis.level == "aa")
        expect(config.analysis.low_memory)

    def test_engine_config_to_dict(self):
        """Test EngineConfig to_dict() method for backwards compatibility."""
        config = EngineConfig.create_default()
        result = config.to_dict()

        expect(isinstance(result, dict))
        expect(not ("aggressive" not in result))
        expect(not ("force_different" not in result))
        expect(not ("nop" not in result))
        expect(isinstance(result["nop"], dict))
        expect(not ("substitution" not in result))
        expect(isinstance(result["substitution"], dict))
        expect(not ("register" not in result))
        expect(isinstance(result["register"], dict))
        expect(not ("analysis" not in result))
        expect(isinstance(result["analysis"], dict))

    def test_engine_config_to_dict_nested_values(self):
        """Test that to_dict() correctly nests sub-config values."""
        config = EngineConfig.create_aggressive()
        result = config.to_dict()

        expect(result["aggressive"])
        expect(result["nop"]["max_per_function"] == _EXPECTED_RESULT_NOP_MAX_PER_FUNCTION_20)
        expect(result["nop"]["use_creative_nops"])
        expect(
            result["substitution"]["max_substitutions_per_function"]
            == _EXPECTED_RESULT_SUBSTITUTION_MAX_SUBSTITUTIONS_PER_FUN_30
        )
        expect(result["analysis"]["level"] == "aaa")


class TestConfigImmutability:
    """Tests for config object behavior."""

    def test_mutation_config_modifiable(self):
        """Test that config fields can be modified after creation."""
        config = MutationConfig()
        config.max_per_function = 20
        expect(config.max_per_function == _EXPECTED_CONFIG_MAX_PER_FUNCTION_20)

    def test_engine_config_nested_modification(self):
        """Test modifying nested config objects."""
        config = EngineConfig()
        config.nop.max_per_function = 15
        expect(config.nop.max_per_function == _EXPECTED_CONFIG_NOP_MAX_PER_FUNCTION_15)


class TestConfigComparison:
    """Tests comparing different config factory outputs."""

    def test_default_vs_aggressive_differences(self):
        """Test that default and aggressive configs differ."""
        default = EngineConfig.create_default()
        aggressive = EngineConfig.create_aggressive()

        expect(default.aggressive != aggressive.aggressive)
        expect(not (default.nop.probability >= aggressive.nop.probability))
        expect(not (default.nop.max_per_function >= aggressive.nop.max_per_function))

    def test_default_vs_memory_efficient_differences(self):
        """Test that default and memory_efficient configs differ."""
        default = EngineConfig.create_default()
        memory_efficient = EngineConfig.create_memory_efficient()

        expect(not (default.nop.max_per_function <= memory_efficient.nop.max_per_function))
        expect(not (default.nop.probability <= memory_efficient.nop.probability))
        expect(default.analysis.low_memory != memory_efficient.analysis.low_memory)
