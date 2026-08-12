"""Static pass-dependency catalogs for mutation ordering."""

from __future__ import annotations

from r2morph.mutations.pass_dependency_models import DependencyType, PassDependency


def default_pass_dependencies() -> list[PassDependency]:
    return [
        PassDependency(
            "control_flow_flattening",
            "block_reordering",
            DependencyType.REQUIRES_ABSENCE,
            "Control flow flattening should run before block reordering",
        ),
        PassDependency(
            "full_control_flow_flattening",
            "block_reordering",
            DependencyType.REQUIRES_ABSENCE,
            "Full CFF should run before block reordering",
        ),
        PassDependency(
            "block_reordering",
            "nop_insertion",
            DependencyType.RECOMMENDS,
            "Block reordering works better after nop insertion",
        ),
        PassDependency(
            "dead_code_injection",
            "nop_insertion",
            DependencyType.RECOMMENDS,
            "Dead code injection benefits from nop padding",
        ),
        PassDependency(
            "instruction_substitution",
            "register_substitution",
            DependencyType.CONFLICTS_WITH,
            "Instruction and register substitution may conflict on same instructions",
            True,
        ),
        PassDependency(
            "control_flow_flattening",
            "instruction_substitution",
            DependencyType.REQUIRES,
            "CFF requires substitution support for dispatcher code",
            True,
        ),
        PassDependency(
            "block_reordering",
            "control_flow_flattening",
            DependencyType.CONFLICTS_WITH,
            "Block reordering invalidates CFF state mapping",
        ),
        PassDependency(
            "register_substitution",
            "nop_insertion",
            DependencyType.RECOMMENDS,
            "Register substitution provides more opportunities for nop insertion",
        ),
        PassDependency(
            "instruction_expansion",
            "dead_code_injection",
            DependencyType.RECOMMENDS,
            "Instruction expansion creates more space for dead code",
        ),
    ]
