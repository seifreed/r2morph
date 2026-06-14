"""Static pass-dependency catalogs for mutation ordering."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from r2morph.mutations.pass_dependency_models import PassDependency


def default_pass_dependencies() -> list[PassDependency]:
    from r2morph.mutations.pass_dependency_models import DependencyType, PassDependency

    return [
        PassDependency(
            source_pass="control_flow_flattening",
            target_pass="block_reordering",
            dep_type=DependencyType.REQUIRES_ABSENCE,
            reason="Control flow flattening should run before block reordering",
        ),
        PassDependency(
            source_pass="full_control_flow_flattening",
            target_pass="block_reordering",
            dep_type=DependencyType.REQUIRES_ABSENCE,
            reason="Full CFF should run before block reordering",
        ),
        PassDependency(
            source_pass="block_reordering",
            target_pass="nop_insertion",
            dep_type=DependencyType.RECOMMENDS,
            reason="Block reordering works better after nop insertion",
        ),
        PassDependency(
            source_pass="dead_code_injection",
            target_pass="nop_insertion",
            dep_type=DependencyType.RECOMMENDS,
            reason="Dead code injection benefits from nop padding",
        ),
        PassDependency(
            source_pass="instruction_substitution",
            target_pass="register_substitution",
            dep_type=DependencyType.CONFLICTS_WITH,
            reason="Instruction and register substitution may conflict on same instructions",
            optional=True,
        ),
        PassDependency(
            source_pass="control_flow_flattening",
            target_pass="instruction_substitution",
            dep_type=DependencyType.REQUIRES,
            reason="CFF requires substitution support for dispatcher code",
            optional=True,
        ),
        PassDependency(
            source_pass="block_reordering",
            target_pass="control_flow_flattening",
            dep_type=DependencyType.CONFLICTS_WITH,
            reason="Block reordering invalidates CFF state mapping",
        ),
        PassDependency(
            source_pass="register_substitution",
            target_pass="nop_insertion",
            dep_type=DependencyType.RECOMMENDS,
            reason="Register substitution provides more opportunities for nop insertion",
        ),
        PassDependency(
            source_pass="instruction_expansion",
            target_pass="dead_code_injection",
            dep_type=DependencyType.RECOMMENDS,
            reason="Instruction expansion creates more space for dead code",
        ),
    ]
