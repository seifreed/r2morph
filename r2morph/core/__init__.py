"""Core public API, loaded lazily to keep layer imports acyclic."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_LAZY_EXPORTS = {
    "AnalysisCache": "r2morph.core.analysis_cache",
    "CacheEntry": "r2morph.core.analysis_cache_models",
    "CacheKey": "r2morph.core.analysis_cache_models",
    "CacheStats": "r2morph.core.analysis_cache_models",
    "CacheStorage": "r2morph.core.analysis_cache_storage",
    "compute_binary_hash": "r2morph.core.analysis_cache",
    "compute_partial_hash": "r2morph.core.analysis_cache",
    "REGISTER_ENCODING": "r2morph.core.assembly",
    "AssemblyService": "r2morph.core.assembly",
    "get_assembly_service": "r2morph.core.assembly",
    "Binary": "r2morph.core.binary",
    "AnalysisConfig": "r2morph.core.config",
    "EngineConfig": "r2morph.core.config",
    "InstructionSubstitutionConfig": "r2morph.core.config",
    "MutationConfig": "r2morph.core.config",
    "NopInsertionConfig": "r2morph.core.config",
    "RegisterSubstitutionConfig": "r2morph.core.config",
    "AVG_INSTRUCTION_SIZE_BYTES": "r2morph.core.constants",
    "BATCH_MUTATION_CHECKPOINT": "r2morph.core.constants",
    "HIGH_ENTROPY_THRESHOLD": "r2morph.core.constants",
    "LARGE_BINARY_THRESHOLD_MB": "r2morph.core.constants",
    "LARGE_FUNCTION_COUNT_THRESHOLD": "r2morph.core.constants",
    "MANY_FUNCTIONS_THRESHOLD": "r2morph.core.constants",
    "MEDIUM_FUNCTION_COUNT_THRESHOLD": "r2morph.core.constants",
    "MINIMUM_FUNCTION_SIZE": "r2morph.core.constants",
    "PACKED_ENTROPY_THRESHOLD": "r2morph.core.constants",
    "SMALL_FUNCTION_THRESHOLD": "r2morph.core.constants",
    "VERY_LARGE_BINARY_THRESHOLD_MB": "r2morph.core.constants",
    "VERY_MANY_FUNCTIONS_THRESHOLD": "r2morph.core.constants",
    "MorphEngine": "r2morph.core.engine",
    "Function": "r2morph.core.function",
    "Instruction": "r2morph.core.instruction",
    "MemoryManager": "r2morph.core.memory_manager",
    "get_memory_manager": "r2morph.core.memory_manager",
    "DependencyResolver": "r2morph.core.parallel",
    "ExecutionPlan": "r2morph.core.parallel",
    "ParallelMutationEngine": "r2morph.core.parallel",
    "PassDependency": "r2morph.core.parallel",
    "PassResult": "r2morph.core.parallel",
    "PassStatus": "r2morph.core.parallel",
    "execute_parallel": "r2morph.core.parallel",
    "ParallelMutator": "r2morph.core.parallel_executor",
    "MutationResult": "r2morph.core.parallel_executor_models",
    "MutationTask": "r2morph.core.parallel_executor_models",
    "ResolutionStrategy": "r2morph.core.parallel_executor_models",
    "TaskStatus": "r2morph.core.parallel_executor_models",
    "ResultMerger": "r2morph.core.parallel_result_merger",
    "WorkQueue": "r2morph.core.parallel_work_queue",
    "BinaryReader": "r2morph.core.reader",
    "BinaryWriter": "r2morph.core.writer",
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    if name in _LAZY_EXPORTS:
        module = import_module(_LAZY_EXPORTS[name])
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
