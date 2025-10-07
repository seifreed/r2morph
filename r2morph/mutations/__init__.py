"""
Mutation passes for binary transformations.
"""

from r2morph.mutations.base import MutationPass
from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass

__all__ = [
    "MutationPass",
    "NopInsertionPass",
    "InstructionSubstitutionPass",
    "BlockReorderingPass",
    "RegisterSubstitutionPass",
    "InstructionExpansionPass",
]
