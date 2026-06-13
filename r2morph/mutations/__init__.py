"""
Mutation passes for binary transformations.
"""

from r2morph.mutations.abi_aware_base import (
    ABIAwareMutationPass,
    ABIResult,
    ABIValidationError,
    create_abi_aware_pass,
)
from r2morph.mutations.abi_hook import (
    ABICheckResult,
    ABIMutationHook,
    ABISnapshot,
    ABIViolationAction,
    create_abi_hook,
)
from r2morph.mutations.base import MutationPass, MutationRecord, MutationResult, PassSupport
from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.mutations.cfg_aware import CFGAwareMutationPass
from r2morph.mutations.conflict_detector import (
    Conflict,
    ConflictDetector,
    ConflictSeverity,
    ConflictType,
    MutationRegion,
    RegionTracker,
    Resolution,
    analyze_mutations_for_conflicts,
)
from r2morph.mutations.constant_unfolding import ConstantUnfoldingPass
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from r2morph.mutations.data_flow_mutation import DataFlowMutationPass
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.mutations.hardened_base import (
    HardenedMutationPass,
)
from r2morph.mutations.hardened_cff import (
    HardenedControlFlowFlattening,
    create_hardened_cff_pass,
)
from r2morph.mutations.hardened_opaque import (
    HardenedOpaquePredicates,
    create_hardened_opaque_pass,
)
from r2morph.mutations.import_obfuscation import ImportTableObfuscationPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.parallel_executor import (
    MutationResult as ParallelMutationResult,
)
from r2morph.mutations.parallel_executor import (
    MutationTask,
    ParallelMutator,
    ParallelStats,
    create_parallel_executor,
)
from r2morph.mutations.pass_dependencies import (
    DependencyType,
    DependencyViolation,
    PassDependency,
    PassDependencyRegistry,
    get_pass_dependency_registry,
    suggest_pipeline_order,
    validate_pipeline_order,
)
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from r2morph.mutations.string_obfuscation import StringObfuscationPass

__all__ = [
    "MutationPass",
    "PassSupport",
    "MutationRecord",
    "MutationResult",
    "NopInsertionPass",
    "InstructionSubstitutionPass",
    "BlockReorderingPass",
    "RegisterSubstitutionPass",
    "InstructionExpansionPass",
    "ControlFlowFlatteningPass",
    "DeadCodeInjectionPass",
    "CFGAwareMutationPass",
    # Hardened mutations
    "HardenedMutationPass",
    "HardenedControlFlowFlattening",
    "HardenedOpaquePredicates",
    "create_hardened_cff_pass",
    "create_hardened_opaque_pass",
    # ABI hooks
    "ABIMutationHook",
    "ABICheckResult",
    "ABISnapshot",
    "ABIViolationAction",
    "create_abi_hook",
    "ABIResult",
    "ABIValidationError",
    "ABIAwareMutationPass",
    "create_abi_aware_pass",
    # Pass dependencies
    "DependencyType",
    "PassDependency",
    "DependencyViolation",
    "PassDependencyRegistry",
    "get_pass_dependency_registry",
    "validate_pipeline_order",
    "suggest_pipeline_order",
    # Conflict detection
    "Conflict",
    "ConflictDetector",
    "ConflictSeverity",
    "ConflictType",
    "MutationRegion",
    "RegionTracker",
    "Resolution",
    "analyze_mutations_for_conflicts",
    # New mutations
    "DataFlowMutationPass",
    "StringObfuscationPass",
    "ImportTableObfuscationPass",
    "ConstantUnfoldingPass",
    # Parallel executor
    "ParallelMutator",
    "MutationTask",
    "ParallelMutationResult",
    "ParallelStats",
    "create_parallel_executor",
]
