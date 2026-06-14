"""Result shaping helpers for symbolic path exploration."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.analysis.symbolic.path_explorer_models import ExplorationResult, ExplorationStrategy
from r2morph.analysis.symbolic.path_explorer_techniques import (
    OpaquePredicateDetectionTechnique,
    VMHandlerDetectionTechnique,
)

logger = logging.getLogger(__name__)


def collect_exploration_results(
    simgr: Any,
    strategy: ExplorationStrategy,
    execution_time: float,
    exploration_techniques: dict[ExplorationStrategy, Any],
) -> ExplorationResult:
    """Collect and analyze results from path exploration."""
    result = ExplorationResult(execution_time=execution_time)

    interesting_states = []
    if hasattr(simgr, "found"):
        interesting_states.extend(simgr.found)
    if hasattr(simgr, "deadended"):
        interesting_states.extend(simgr.deadended)

    result.interesting_paths = interesting_states

    if strategy == ExplorationStrategy.VM_HANDLER:
        technique = exploration_techniques[strategy]
        if isinstance(technique, VMHandlerDetectionTechnique):
            result.vm_handlers_found = len(technique.handler_patterns)
    elif strategy == ExplorationStrategy.OPAQUE_PREDICATE:
        technique = exploration_techniques[strategy]
        if isinstance(technique, OpaquePredicateDetectionTechnique):
            result.opaque_predicates_found = len(technique.opaque_candidates)

    constraints = []
    for state in interesting_states:
        try:
            if hasattr(state, "solver"):
                constraints.extend(state.solver.constraints)
        except Exception as exc:
            logger.debug(f"Error collecting constraints: {exc}")

    result.constraints_collected = constraints
    return result


def build_vm_handlers(
    technique: Any,
) -> list[dict[str, Any]]:
    """Materialize discovered VM handlers into plain dicts."""
    handlers: list[dict[str, Any]] = []
    if isinstance(technique, VMHandlerDetectionTechnique):
        for handler_addr in technique.handler_patterns:
            handlers.append(
                {
                    "address": handler_addr,
                    "type": "unknown",
                    "confidence": 0.8,
                }
            )
    return handlers


def build_opaque_predicates(
    technique: Any,
) -> list[dict[str, Any]]:
    """Materialize opaque-predicate findings into plain dicts."""
    predicates: list[dict[str, Any]] = []
    if isinstance(technique, OpaquePredicateDetectionTechnique):
        for predicate_addr in technique.opaque_candidates:
            outcomes = technique.branch_outcomes.get(predicate_addr, [])
            predicates.append(
                {
                    "address": predicate_addr,
                    "always_taken": all(outcomes) if outcomes else None,
                    "sample_count": len(outcomes),
                    "confidence": min(1.0, len(outcomes) / 10.0),
                }
            )
    return predicates
