"""
Typed configuration dataclasses for r2morph.

This module provides strongly-typed configuration classes to replace raw
dictionaries throughout the codebase, improving type safety and IDE support.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MutationConfig:
    """Base configuration for mutation passes."""

    max_per_function: int = 5
    probability: float = 0.5
    force_different: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for backward compatibility."""
        return {
            "max_per_function": self.max_per_function,
            "probability": self.probability,
            "force_different": self.force_different,
        }


@dataclass
class NopInsertionConfig(MutationConfig):
    """Configuration for NOP insertion pass."""

    use_creative_nops: bool = True
    max_nops_per_function: int = 5

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for backward compatibility."""
        base = super().to_dict()
        base.update(
            {
                "use_creative_nops": self.use_creative_nops,
                "max_nops_per_function": self.max_nops_per_function,
            }
        )
        return base


@dataclass
class InstructionSubstitutionConfig(MutationConfig):
    """Configuration for instruction substitution pass."""

    max_substitutions_per_function: int = 10

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for backward compatibility."""
        base = super().to_dict()
        base.update(
            {
                "max_substitutions_per_function": self.max_substitutions_per_function,
            }
        )
        return base


@dataclass
class RegisterSubstitutionConfig(MutationConfig):
    """Configuration for register substitution pass."""

    max_substitutions_per_function: int = 5

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for backward compatibility."""
        base = super().to_dict()
        base.update(
            {
                "max_substitutions_per_function": self.max_substitutions_per_function,
            }
        )
        return base


@dataclass
class InstructionExpansionConfig(MutationConfig):
    """Configuration for instruction expansion pass."""

    max_expansions_per_function: int = 5
    max_expansion_size: int = 4

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for backward compatibility."""
        base = super().to_dict()
        base.update(
            {
                "max_expansions_per_function": self.max_expansions_per_function,
                "max_expansion_size": self.max_expansion_size,
            }
        )
        return base


@dataclass
class BlockReorderingConfig(MutationConfig):
    """Configuration for block reordering pass."""

    max_reorderings_per_function: int = 3
    max_functions: int = 10
    preserve_fallthrough: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for backward compatibility."""
        base = super().to_dict()
        base.update(
            {
                "max_reorderings_per_function": self.max_reorderings_per_function,
                "max_functions": self.max_functions,
                "preserve_fallthrough": self.preserve_fallthrough,
            }
        )
        return base


@dataclass
class AnalysisConfig:
    """Configuration for binary analysis."""

    level: str = "auto"
    timeout_seconds: int = 300
    low_memory: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for backward compatibility."""
        return {
            "level": self.level,
            "timeout_seconds": self.timeout_seconds,
            "low_memory": self.low_memory,
        }


@dataclass
class EngineConfig:
    """Main engine configuration."""

    aggressive: bool = False
    force_different: bool = False
    nop: NopInsertionConfig = field(default_factory=NopInsertionConfig)
    substitution: InstructionSubstitutionConfig = field(
        default_factory=InstructionSubstitutionConfig
    )
    register: RegisterSubstitutionConfig = field(
        default_factory=RegisterSubstitutionConfig
    )
    expansion: InstructionExpansionConfig = field(
        default_factory=InstructionExpansionConfig
    )
    block: BlockReorderingConfig = field(default_factory=BlockReorderingConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for backward compatibility."""
        return {
            "aggressive": self.aggressive,
            "force_different": self.force_different,
            "nop": self.nop.to_dict(),
            "substitution": self.substitution.to_dict(),
            "register": self.register.to_dict(),
            "expansion": self.expansion.to_dict(),
            "block": self.block.to_dict(),
            "analysis": self.analysis.to_dict(),
        }

    @classmethod
    def create_default(cls) -> "EngineConfig":
        """
        Create a default (conservative) configuration.

        Returns:
            EngineConfig with conservative settings for safe transformations.
        """
        return cls(
            aggressive=False,
            force_different=False,
            nop=NopInsertionConfig(
                max_per_function=5,
                probability=0.5,
                use_creative_nops=True,
                max_nops_per_function=5,
            ),
            substitution=InstructionSubstitutionConfig(
                max_per_function=5,
                probability=0.7,
                max_substitutions_per_function=10,
            ),
            register=RegisterSubstitutionConfig(
                max_per_function=5,
                probability=0.5,
                max_substitutions_per_function=5,
            ),
            expansion=InstructionExpansionConfig(
                max_per_function=5,
                probability=0.5,
                max_expansions_per_function=5,
            ),
            block=BlockReorderingConfig(
                max_per_function=3,
                probability=0.3,
                max_reorderings_per_function=3,
            ),
            analysis=AnalysisConfig(
                level="auto",
                timeout_seconds=300,
                low_memory=False,
            ),
        )

    @classmethod
    def create_aggressive(cls) -> "EngineConfig":
        """
        Create an aggressive configuration for maximum transformation.

        Returns:
            EngineConfig with aggressive settings for heavy transformations.
        """
        return cls(
            aggressive=True,
            force_different=True,
            nop=NopInsertionConfig(
                max_per_function=20,
                probability=0.95,
                force_different=True,
                use_creative_nops=True,
                max_nops_per_function=20,
            ),
            substitution=InstructionSubstitutionConfig(
                max_per_function=30,
                probability=0.95,
                force_different=True,
                max_substitutions_per_function=30,
            ),
            register=RegisterSubstitutionConfig(
                max_per_function=15,
                probability=0.9,
                force_different=True,
                max_substitutions_per_function=15,
            ),
            expansion=InstructionExpansionConfig(
                max_per_function=15,
                probability=0.9,
                force_different=True,
                max_expansions_per_function=15,
            ),
            block=BlockReorderingConfig(
                max_per_function=8,
                probability=0.8,
                force_different=True,
                max_reorderings_per_function=8,
            ),
            analysis=AnalysisConfig(
                level="aaa",
                timeout_seconds=600,
                low_memory=False,
            ),
        )

    @classmethod
    def create_memory_efficient(cls) -> "EngineConfig":
        """
        Create a memory-efficient configuration for large binaries.

        Returns:
            EngineConfig with reduced settings to prevent OOM on large binaries.
        """
        return cls(
            aggressive=False,
            force_different=False,
            nop=NopInsertionConfig(
                max_per_function=2,
                probability=0.3,
                use_creative_nops=False,
                max_nops_per_function=2,
            ),
            substitution=InstructionSubstitutionConfig(
                max_per_function=2,
                probability=0.3,
                max_substitutions_per_function=5,
            ),
            register=RegisterSubstitutionConfig(
                max_per_function=2,
                probability=0.3,
                max_substitutions_per_function=2,
            ),
            expansion=InstructionExpansionConfig(
                max_per_function=2,
                probability=0.3,
                max_expansions_per_function=2,
            ),
            block=BlockReorderingConfig(
                max_per_function=2,
                probability=0.2,
                max_reorderings_per_function=2,
            ),
            analysis=AnalysisConfig(
                level="aa",
                timeout_seconds=600,
                low_memory=True,
            ),
        )
