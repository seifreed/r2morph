"""Default wiring helpers for the polymorphic engine."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.polymorphic_engine_models import EngineState
from r2morph.mutations.polymorphic_engine_noop import NoOp


def setup_default_engine(
    engine: Any,
    *,
    enable_substitution: bool = True,
    enable_dead_code: bool = True,
    enable_reordering: bool = True,
    enable_flattening: bool = True,
    enable_virtualization: bool = False,
    enable_string_obfuscation: bool = True,
    enable_mobility: bool = False,
    enable_outlining: bool = False,
) -> EngineState:
    """Register the default mutation pipeline on an engine."""
    from r2morph.mutations.block_reordering import BlockReorderingPass
    from r2morph.mutations.code_mobility import CodeMobilityPass
    from r2morph.mutations.code_virtualization import CodeVirtualizationPass
    from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
    from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
    from r2morph.mutations.function_outlining import FunctionOutliningPass
    from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
    from r2morph.mutations.string_obfuscation import StringObfuscationPass

    state = EngineState.INIT

    if enable_substitution:
        engine.add_mutation("InstructionSubstitution", InstructionSubstitutionPass())
        engine.add_transition(
            EngineState.INIT,
            EngineState.SUBSTITUTED,
            "InstructionSubstitution",
            probability=0.8,
        )
        state = EngineState.SUBSTITUTED

    if enable_dead_code:
        from_state = state
        to_state = EngineState.DEAD_CODE_INJECTED
        engine.add_mutation("DeadCodeInjection", DeadCodeInjectionPass())
        engine.add_transition(
            from_state,
            to_state,
            "DeadCodeInjection",
            probability=0.7,
        )
        state = to_state

    if enable_reordering:
        from_state = state
        to_state = EngineState.REORDERED
        engine.add_mutation("BlockReordering", BlockReorderingPass())
        engine.add_transition(
            from_state,
            to_state,
            "BlockReordering",
            probability=0.6,
        )
        state = to_state

    if enable_flattening:
        from_state = state
        to_state = EngineState.FLATTENED
        engine.add_mutation("ControlFlowFlattening", ControlFlowFlatteningPass())
        engine.add_transition(
            from_state,
            to_state,
            "ControlFlowFlattening",
            probability=0.5,
        )
        state = to_state

    if enable_string_obfuscation:
        from_state = state
        to_state = EngineState.STRING_OBFUSCATED
        engine.add_mutation("StringObfuscation", StringObfuscationPass())
        engine.add_transition(
            from_state,
            to_state,
            "StringObfuscation",
            probability=0.6,
        )
        state = to_state

    if enable_virtualization:
        from_state = state
        to_state = EngineState.VIRTUALIZED
        engine.add_mutation("CodeVirtualization", CodeVirtualizationPass())
        engine.add_transition(
            from_state,
            to_state,
            "CodeVirtualization",
            probability=0.3,
        )
        state = to_state

    if enable_mobility:
        from_state = state
        to_state = EngineState.MOBILIZED
        engine.add_mutation("CodeMobility", CodeMobilityPass())
        engine.add_transition(
            from_state,
            to_state,
            "CodeMobility",
            probability=0.4,
        )
        state = to_state

    if enable_outlining:
        from_state = state
        to_state = EngineState.OUTLINED
        engine.add_mutation("FunctionOutlining", FunctionOutliningPass())
        engine.add_transition(
            from_state,
            to_state,
            "FunctionOutlining",
            probability=0.3,
        )
        state = to_state

    engine.add_mutation("NoOp", NoOp())
    engine.add_transition(
        state,
        EngineState.FINAL,
        "NoOp",
        probability=1.0,
    )
    return state


__all__ = ["setup_default_engine"]
