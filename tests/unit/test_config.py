"""
Unit tests for configuration dataclasses.
"""

import importlib.util

import pytest

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)

from r2morph.core.config import (
    MutationConfig,
    NopInsertionConfig,
    InstructionSubstitutionConfig,
    RegisterSubstitutionConfig,
    AnalysisConfig,
    EngineConfig,
)


class TestMutationConfig:
    """Tests for MutationConfig base dataclass."""

    def test_mutation_config_defaults(self):
        """Test MutationConfig default values."""
        config = MutationConfig()
        assert config.max_per_function == 5
        assert config.probability == 0.5
        assert config.force_different == False

    def test_mutation_config_custom_values(self):
        """Test MutationConfig with custom values."""
        config = MutationConfig(
            max_per_function=10,
            probability=0.8,
            force_different=True
        )
        assert config.max_per_function == 10
        assert config.probability == 0.8
        assert config.force_different == True

    def test_mutation_config_to_dict(self):
        """Test MutationConfig to_dict() method."""
        config = MutationConfig(max_per_function=7, probability=0.6, force_different=True)
        result = config.to_dict()

        assert isinstance(result, dict)
        assert result["max_per_function"] == 7
        assert result["probability"] == 0.6
        assert result["force_different"] == True


class TestNopInsertionConfig:
    """Tests for NopInsertionConfig dataclass."""

    def test_nop_insertion_config_defaults(self):
        """Test NopInsertionConfig default values."""
        config = NopInsertionConfig()
        # Inherited defaults
        assert config.max_per_function == 5
        assert config.probability == 0.5
        assert config.force_different == False
        # Own defaults
        assert config.use_creative_nops == True
        assert config.max_nops_per_function == 5

    def test_nop_insertion_config_custom_values(self):
        """Test NopInsertionConfig with custom values."""
        config = NopInsertionConfig(
            max_per_function=8,
            probability=0.7,
            force_different=True,
            use_creative_nops=False,
            max_nops_per_function=12
        )
        assert config.max_per_function == 8
        assert config.probability == 0.7
        assert config.force_different == True
        assert config.use_creative_nops == False
        assert config.max_nops_per_function == 12

    def test_nop_insertion_config_to_dict(self):
        """Test NopInsertionConfig to_dict() includes all fields."""
        config = NopInsertionConfig(
            max_per_function=3,
            use_creative_nops=False,
            max_nops_per_function=7
        )
        result = config.to_dict()

        assert isinstance(result, dict)
        # Base fields
        assert "max_per_function" in result
        assert result["max_per_function"] == 3
        # NOP-specific fields
        assert "use_creative_nops" in result
        assert result["use_creative_nops"] == False
        assert "max_nops_per_function" in result
        assert result["max_nops_per_function"] == 7


class TestInstructionSubstitutionConfig:
    """Tests for InstructionSubstitutionConfig dataclass."""

    def test_instruction_substitution_config_defaults(self):
        """Test InstructionSubstitutionConfig default values."""
        config = InstructionSubstitutionConfig()
        assert config.max_per_function == 5
        assert config.probability == 0.5
        assert config.max_substitutions_per_function == 10

    def test_instruction_substitution_config_to_dict(self):
        """Test InstructionSubstitutionConfig to_dict() method."""
        config = InstructionSubstitutionConfig(
            max_substitutions_per_function=15
        )
        result = config.to_dict()

        assert "max_substitutions_per_function" in result
        assert result["max_substitutions_per_function"] == 15


class TestRegisterSubstitutionConfig:
    """Tests for RegisterSubstitutionConfig dataclass."""

    def test_register_substitution_config_defaults(self):
        """Test RegisterSubstitutionConfig default values."""
        config = RegisterSubstitutionConfig()
        assert config.max_per_function == 5
        assert config.probability == 0.5
        assert config.max_substitutions_per_function == 5

    def test_register_substitution_config_to_dict(self):
        """Test RegisterSubstitutionConfig to_dict() method."""
        config = RegisterSubstitutionConfig(
            max_substitutions_per_function=8
        )
        result = config.to_dict()

        assert "max_substitutions_per_function" in result
        assert result["max_substitutions_per_function"] == 8


class TestAnalysisConfig:
    """Tests for AnalysisConfig dataclass."""

    def test_analysis_config_defaults(self):
        """Test AnalysisConfig default values."""
        config = AnalysisConfig()
        assert config.level == "auto"
        assert config.timeout_seconds == 300
        assert config.low_memory == False

    def test_analysis_config_custom_values(self):
        """Test AnalysisConfig with custom values."""
        config = AnalysisConfig(
            level="aaa",
            timeout_seconds=600,
            low_memory=True
        )
        assert config.level == "aaa"
        assert config.timeout_seconds == 600
        assert config.low_memory == True

    def test_analysis_config_to_dict(self):
        """Test AnalysisConfig to_dict() method."""
        config = AnalysisConfig(level="aa", timeout_seconds=120, low_memory=True)
        result = config.to_dict()

        assert result["level"] == "aa"
        assert result["timeout_seconds"] == 120
        assert result["low_memory"] == True


class TestEngineConfig:
    """Tests for EngineConfig main configuration."""

    def test_engine_config_defaults(self):
        """Test EngineConfig default values."""
        config = EngineConfig()
        assert config.aggressive == False
        assert config.force_different == False
        assert isinstance(config.nop, NopInsertionConfig)
        assert isinstance(config.substitution, InstructionSubstitutionConfig)
        assert isinstance(config.register, RegisterSubstitutionConfig)
        assert isinstance(config.analysis, AnalysisConfig)

    def test_engine_config_factory_default(self):
        """Test EngineConfig.create_default() factory method."""
        config = EngineConfig.create_default()

        assert config.aggressive == False
        assert config.force_different == False
        assert config.nop.max_per_function == 5
        assert config.nop.probability == 0.5
        assert config.nop.use_creative_nops == True
        assert config.substitution.max_substitutions_per_function == 10
        assert config.analysis.level == "auto"
        assert config.analysis.low_memory == False

    def test_engine_config_factory_aggressive(self):
        """Test EngineConfig.create_aggressive() factory method."""
        config = EngineConfig.create_aggressive()

        assert config.aggressive == True
        assert config.force_different == True
        assert config.nop.max_per_function == 20
        assert config.nop.probability == 0.95
        assert config.nop.force_different == True
        assert config.nop.max_nops_per_function == 20
        assert config.nop.use_creative_nops == True
        assert config.substitution.max_per_function == 30
        assert config.substitution.probability == 0.95
        assert config.substitution.max_substitutions_per_function == 30
        assert config.substitution.force_different == True
        assert config.register.max_per_function == 15
        assert config.register.probability == 0.9
        assert config.register.max_substitutions_per_function == 15
        assert config.register.force_different == True
        assert config.expansion.max_per_function == 15
        assert config.expansion.probability == 0.9
        assert config.expansion.max_expansions_per_function == 15
        assert config.expansion.force_different == True
        assert config.block.max_per_function == 8
        assert config.block.probability == 0.8
        assert config.block.max_reorderings_per_function == 8
        assert config.block.force_different == True
        assert config.analysis.level == "aaa"
        assert config.analysis.timeout_seconds == 600

    def test_engine_config_factory_memory_efficient(self):
        """Test EngineConfig.create_memory_efficient() factory method."""
        config = EngineConfig.create_memory_efficient()

        assert config.aggressive == False
        assert config.force_different == False
        assert config.nop.max_per_function == 2
        assert config.nop.probability == 0.3
        assert config.nop.use_creative_nops == False
        assert config.substitution.max_per_function == 2
        assert config.register.max_substitutions_per_function == 2
        assert config.analysis.level == "aa"
        assert config.analysis.low_memory == True

    def test_engine_config_to_dict(self):
        """Test EngineConfig to_dict() method for backwards compatibility."""
        config = EngineConfig.create_default()
        result = config.to_dict()

        assert isinstance(result, dict)
        assert "aggressive" in result
        assert "force_different" in result
        assert "nop" in result
        assert isinstance(result["nop"], dict)
        assert "substitution" in result
        assert isinstance(result["substitution"], dict)
        assert "register" in result
        assert isinstance(result["register"], dict)
        assert "analysis" in result
        assert isinstance(result["analysis"], dict)

    def test_engine_config_to_dict_nested_values(self):
        """Test that to_dict() correctly nests sub-config values."""
        config = EngineConfig.create_aggressive()
        result = config.to_dict()

        assert result["aggressive"] == True
        assert result["nop"]["max_per_function"] == 20
        assert result["nop"]["use_creative_nops"] == True
        assert result["substitution"]["max_substitutions_per_function"] == 30
        assert result["analysis"]["level"] == "aaa"


class TestConfigImmutability:
    """Tests for config object behavior."""

    def test_mutation_config_modifiable(self):
        """Test that config fields can be modified after creation."""
        config = MutationConfig()
        config.max_per_function = 20
        assert config.max_per_function == 20

    def test_engine_config_nested_modification(self):
        """Test modifying nested config objects."""
        config = EngineConfig()
        config.nop.max_per_function = 15
        assert config.nop.max_per_function == 15


class TestConfigComparison:
    """Tests comparing different config factory outputs."""

    def test_default_vs_aggressive_differences(self):
        """Test that default and aggressive configs differ."""
        default = EngineConfig.create_default()
        aggressive = EngineConfig.create_aggressive()

        assert default.aggressive != aggressive.aggressive
        assert default.nop.probability < aggressive.nop.probability
        assert default.nop.max_per_function < aggressive.nop.max_per_function

    def test_default_vs_memory_efficient_differences(self):
        """Test that default and memory_efficient configs differ."""
        default = EngineConfig.create_default()
        memory_efficient = EngineConfig.create_memory_efficient()

        assert default.nop.max_per_function > memory_efficient.nop.max_per_function
        assert default.nop.probability > memory_efficient.nop.probability
        assert default.analysis.low_memory != memory_efficient.analysis.low_memory
