"""Default wiring helpers for the polymorphic engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.mutations.code_mobility import CodeMobilityPass
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.mutations.function_outlining import FunctionOutliningPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.pattern_substitution import PatternSubstitutionPass
from r2morph.mutations.polymorphic_engine_models import EngineState
from r2morph.mutations.polymorphic_engine_noop import NoOp
from r2morph.mutations.string_obfuscation import StringObfuscationPass


@dataclass(frozen=True)
class EngineSetupConfig:
    enable_substitution: bool = True
    enable_pattern_substitution: bool = True
    enable_dead_code: bool = True
    enable_reordering: bool = True
    enable_flattening: bool = True
    enable_virtualization: bool = False
    enable_string_obfuscation: bool = True
    enable_mobility: bool = False
    enable_outlining: bool = False


@dataclass(frozen=True)
class _EngineStage:
    option: str
    name: str
    mutation_type: type[Any]
    state: EngineState
    probability: float


_ENGINE_STAGES = (
    _EngineStage(
        "enable_substitution", "InstructionSubstitution", InstructionSubstitutionPass, EngineState.SUBSTITUTED, 0.8
    ),
    _EngineStage(
        "enable_pattern_substitution",
        "PatternSubstitution",
        PatternSubstitutionPass,
        EngineState.PATTERN_SUBSTITUTED,
        0.7,
    ),
    _EngineStage("enable_dead_code", "DeadCodeInjection", DeadCodeInjectionPass, EngineState.DEAD_CODE_INJECTED, 0.7),
    _EngineStage("enable_reordering", "BlockReordering", BlockReorderingPass, EngineState.REORDERED, 0.6),
    _EngineStage(
        "enable_flattening",
        "ControlFlowFlattening",
        ControlFlowFlatteningPass,
        EngineState.FLATTENED,
        0.5,
    ),
    _EngineStage(
        "enable_string_obfuscation",
        "StringObfuscation",
        StringObfuscationPass,
        EngineState.STRING_OBFUSCATED,
        0.6,
    ),
    _EngineStage("enable_virtualization", "CodeVirtualization", CodeVirtualizationPass, EngineState.VIRTUALIZED, 0.3),
    _EngineStage("enable_mobility", "CodeMobility", CodeMobilityPass, EngineState.MOBILIZED, 0.4),
    _EngineStage("enable_outlining", "FunctionOutlining", FunctionOutliningPass, EngineState.OUTLINED, 0.3),
)


def setup_default_engine(engine: Any, config: EngineSetupConfig | None = None) -> EngineState:
    """Register the default mutation pipeline on an engine."""
    config = config or EngineSetupConfig()
    state = EngineState.INIT

    for stage in _ENGINE_STAGES:
        if not getattr(config, stage.option):
            continue
        engine.add_mutation(stage.name, stage.mutation_type())
        engine.add_transition(state, stage.state, stage.name, probability=stage.probability)
        state = stage.state

    engine.add_mutation("NoOp", NoOp())
    engine.add_transition(
        state,
        EngineState.FINAL,
        "NoOp",
        probability=1.0,
    )
    return state


__all__ = ["EngineSetupConfig", "setup_default_engine"]
