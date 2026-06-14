"""Static semantic invariant catalogs."""

from __future__ import annotations

from r2morph.validation.semantic_invariant_models import InvariantCategory, InvariantSpec

STANDARD_INVARIANTS: list[InvariantSpec] = [
    InvariantSpec(
        name="stack_balance",
        category=InvariantCategory.STACK,
        description="Stack pointer must return to original value after function",
        check_required=True,
        pass_types=["nop", "substitute", "register", "block"],
    ),
    InvariantSpec(
        name="callee_saved_preservation",
        category=InvariantCategory.REGISTER,
        description="Callee-saved registers must be preserved",
        check_required=True,
        pass_types=["nop", "substitute", "register"],
    ),
    InvariantSpec(
        name="return_value_preservation",
        category=InvariantCategory.REGISTER,
        description="Return value register(s) must contain correct value",
        check_required=True,
        auto_repair=False,
        pass_types=["substitute", "register"],
    ),
    InvariantSpec(
        name="control_flow_preservation",
        category=InvariantCategory.CONTROL_FLOW,
        description="Control flow must reach original successors",
        check_required=True,
        pass_types=["nop", "substitute", "register", "block"],
    ),
    InvariantSpec(
        name="memory_safety",
        category=InvariantCategory.MEMORY,
        description="Memory accesses must not exceed bounds",
        check_required=True,
        pass_types=["substitute", "register"],
    ),
    InvariantSpec(
        name="no_unintended_writes",
        category=InvariantCategory.SIDE_EFFECT,
        description="Mutation must not introduce unintended memory writes",
        check_required=True,
        pass_types=["substitute", "register"],
    ),
]
