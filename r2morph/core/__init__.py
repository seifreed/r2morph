"""
Core module for r2morph.

Contains the fundamental classes for binary analysis and transformation.
"""

from r2morph.core.assembly import (
    AssemblyService,
    REGISTER_ENCODING,
    get_assembly_service,
)
from r2morph.core.binary import Binary
from r2morph.core.config import (
    AnalysisConfig,
    EngineConfig,
    InstructionSubstitutionConfig,
    MutationConfig,
    NopInsertionConfig,
    RegisterSubstitutionConfig,
)
from r2morph.core.constants import (
    AVG_INSTRUCTION_SIZE_BYTES,
    BATCH_MUTATION_CHECKPOINT,
    HIGH_ENTROPY_THRESHOLD,
    LARGE_BINARY_THRESHOLD_MB,
    LARGE_FUNCTION_COUNT_THRESHOLD,
    MANY_FUNCTIONS_THRESHOLD,
    MEDIUM_FUNCTION_COUNT_THRESHOLD,
    MINIMUM_FUNCTION_SIZE,
    PACKED_ENTROPY_THRESHOLD,
    SMALL_FUNCTION_THRESHOLD,
    VERY_LARGE_BINARY_THRESHOLD_MB,
    VERY_MANY_FUNCTIONS_THRESHOLD,
)
from r2morph.core.engine import MorphEngine
from r2morph.core.function import Function
from r2morph.core.instruction import Instruction
from r2morph.core.memory_manager import (
    MemoryManager,
    get_memory_manager,
)

__all__ = [
    # Core classes
    "Binary",
    "MorphEngine",
    "Function",
    "Instruction",
    # Services (extracted from Binary)
    "AssemblyService",
    "REGISTER_ENCODING",
    "get_assembly_service",
    "MemoryManager",
    "get_memory_manager",
    # Config classes
    "AnalysisConfig",
    "EngineConfig",
    "InstructionSubstitutionConfig",
    "MutationConfig",
    "NopInsertionConfig",
    "RegisterSubstitutionConfig",
    # Constants
    "AVG_INSTRUCTION_SIZE_BYTES",
    "BATCH_MUTATION_CHECKPOINT",
    "HIGH_ENTROPY_THRESHOLD",
    "LARGE_BINARY_THRESHOLD_MB",
    "LARGE_FUNCTION_COUNT_THRESHOLD",
    "MANY_FUNCTIONS_THRESHOLD",
    "MEDIUM_FUNCTION_COUNT_THRESHOLD",
    "MINIMUM_FUNCTION_SIZE",
    "PACKED_ENTROPY_THRESHOLD",
    "SMALL_FUNCTION_THRESHOLD",
    "VERY_LARGE_BINARY_THRESHOLD_MB",
    "VERY_MANY_FUNCTIONS_THRESHOLD",
]
