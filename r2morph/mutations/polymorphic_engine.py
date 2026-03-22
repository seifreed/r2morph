"""
Polymorphic Engine - State machine for iterative mutations.

Orchestrates multiple mutation passes in a state machine pattern,
allowing for iterative transformations that build upon each other.
Each iteration can apply different mutations based on the current state,
creating complex polymorphic variants.

The state machine approach enables:
- Multiple rounds of mutations
- State-dependent mutation selection
- Convergence detection
- Adaptive mutation strategies

Example flow:

    State 0 (INIT):
        -> Apply instruction substitution
        -> Transition to State 1

    State 1 (SUBSTITUTED):
        -> Apply dead code injection
        -> Transition to State 2

    State 2 (DEAD_CODE):
        -> Apply block reordering
        -> Transition to State 3

    State 3 (REORDERED):
        -> Apply control flow flattening
        -> Transition to State 4

    State 4 (FINAL):
        -> Validate and output

Multiple iterations with different seeds produce
different polymorphic variants while maintaining semantics.
"""

import logging
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


class EngineState(Enum):
    """States for the polymorphic engine."""

    INIT = auto()
    SUBSTITUTED = auto()
    DEAD_CODE_INJECTED = auto()
    REORDERED = auto()
    FLATTENED = auto()
    OBFUSCATED = auto()
    VIRTUALIZED = auto()
    STRING_OBFUSCATED = auto()
    MOBILIZED = auto()
    OUTLINED = auto()
    FINAL = auto()


@dataclass
class StateTransition:
    """Represents a state transition in the engine."""

    from_state: EngineState
    to_state: EngineState
    mutation_name: str
    condition: Callable[[dict[str, Any]], bool] | None = None
    probability: float = 1.0


@dataclass
class MutationResult:
    """Result of a single mutation application."""

    name: str
    state_before: EngineState
    state_after: EngineState
    success: bool
    stats: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class EngineRunResult:
    """Result of complete engine run."""

    initial_state: EngineState
    final_state: EngineState
    iterations: int
    mutations_applied: list[MutationResult] = field(default_factory=list)
    final_stats: dict[str, Any] = field(default_factory=dict)
    converged: bool = False


class PolymorphicEngine:
    """
    State machine for polymorphic mutation orchestration.

    Manages state transitions and applies mutations based on current state.
    Supports multiple paths through the state machine, creating
    different mutation sequences for different variants.

    Example:
        engine = PolymorphicEngine(seed=42)
        engine.add_transition(EngineState.INIT, EngineState.SUBSTITUTED, "InstructionSubstitution")
        engine.add_transition(EngineState.SUBSTITUTED, EngineState.DEAD_CODE_INJECTED, "DeadCodeInjection")

        result = engine.run(binary)
    """

    def __init__(self, seed: int | None = None):
        """
        Initialize polymorphic engine.

        Args:
            seed: Random seed for reproducibility
        """
        self.seed = seed
        self.rng = random.Random(seed)
        self.transitions: dict[EngineState, list[StateTransition]] = {}
        self.mutations: dict[str, MutationPass] = {}
        self.current_state = EngineState.INIT
        self.max_iterations = 10
        self.convergence_check: Callable[[dict[str, Any]], bool] | None = None

    def add_mutation(self, name: str, mutation_pass: MutationPass) -> None:
        """
        Register a mutation pass with the engine.

        Args:
            name: Name to identify the mutation
            mutation_pass: The mutation pass instance
        """
        self.mutations[name] = mutation_pass

    def add_transition(
        self,
        from_state: EngineState,
        to_state: EngineState,
        mutation_name: str,
        condition: Callable[[dict[str, Any]], bool] | None = None,
        probability: float = 1.0,
    ) -> None:
        """
        Add a state transition.

        Args:
            from_state: Starting state
            to_state: Target state after mutation
            mutation_name: Name of registered mutation to apply
            condition: Optional condition function (takes stats, returns bool)
            probability: Probability of following this transition
        """
        if from_state not in self.transitions:
            self.transitions[from_state] = []

        transition = StateTransition(
            from_state=from_state,
            to_state=to_state,
            mutation_name=mutation_name,
            condition=condition,
            probability=probability,
        )
        self.transitions[from_state].append(transition)

    def set_convergence_check(self, check: Callable[[dict[str, Any]], bool]) -> None:
        """
        Set a convergence check function.

        The check function takes mutation stats and returns True
        if the engine should stop early (converged).

        Args:
            check: Function that takes stats dict and returns bool
        """
        self.convergence_check = check

    def get_available_transitions(self, state: EngineState) -> list[StateTransition]:
        """
        Get all available transitions from a state.

        Args:
            state: Current state

        Returns:
            List of valid transitions
        """
        return self.transitions.get(state, [])

    def select_transition(self, state: EngineState, stats: dict[str, Any]) -> StateTransition | None:
        """
        Select a transition based on conditions and probabilities.

        Args:
            state: Current state
            stats: Current mutation statistics

        Returns:
            Selected transition or None if no valid transitions
        """
        available = self.get_available_transitions(state)
        if not available:
            return None

        valid_transitions = []
        for trans in available:
            if trans.condition is None or trans.condition(stats):
                valid_transitions.append(trans)

        if not valid_transitions:
            return None

        self.rng.shuffle(valid_transitions)

        for trans in valid_transitions:
            if self.rng.random() <= trans.probability:
                return trans

        if valid_transitions:
            return valid_transitions[0]

        return None

    def run(
        self,
        binary: Binary,
        initial_state: EngineState = EngineState.INIT,
        max_iterations: int | None = None,
    ) -> EngineRunResult:
        """
        Run the polymorphic engine.

        Args:
            binary: Binary to mutate
            initial_state: Starting state
            max_iterations: Maximum iterations (overrides instance setting)

        Returns:
            EngineRunResult with mutation history and final stats
        """
        if max_iterations is None:
            max_iterations = self.max_iterations

        self.current_state = initial_state
        current_stats: dict[str, Any] = {}
        mutations_applied: list[MutationResult] = []
        consecutive_empty = 0
        max_consecutive_empty = 3

        for iteration in range(max_iterations):
            transition = self.select_transition(self.current_state, current_stats)

            if transition is None:
                logger.info(f"No more transitions from state {self.current_state}")
                break

            mutation_name = transition.mutation_name
            mutation = self.mutations.get(mutation_name)

            if mutation is None:
                logger.warning(f"Mutation '{mutation_name}' not registered")
                break

            logger.info(f"Iteration {iteration}: Applying {mutation_name}")

            try:
                mutation_stats = mutation.apply(binary)

                if not mutation_stats or (
                    isinstance(mutation_stats, dict)
                    and mutation_stats.get("mutations", 0) == 0
                    and mutation_stats.get("functions_mutated", 0) == 0
                ):
                    consecutive_empty += 1
                    if consecutive_empty >= max_consecutive_empty:
                        logger.info(f"Stopping: {max_consecutive_empty} consecutive empty mutations")
                        break
                else:
                    consecutive_empty = 0

                current_stats.update(mutation_stats)

                mutation_result = MutationResult(
                    name=mutation_name,
                    state_before=self.current_state,
                    state_after=transition.to_state,
                    success=True,
                    stats=mutation_stats,
                )
                mutations_applied.append(mutation_result)

                self.current_state = transition.to_state

                if self.convergence_check and self.convergence_check(current_stats):
                    logger.info("Convergence check passed, stopping early")
                    break

            except Exception as e:
                logger.error(f"Error applying {mutation_name}: {e}")
                mutation_result = MutationResult(
                    name=mutation_name,
                    state_before=self.current_state,
                    state_after=self.current_state,
                    success=False,
                    error=str(e),
                )
                mutations_applied.append(mutation_result)
                break

        return EngineRunResult(
            initial_state=initial_state,
            final_state=self.current_state,
            iterations=len(mutations_applied),
            mutations_applied=mutations_applied,
            final_stats=current_stats,
            converged=self.current_state == EngineState.FINAL,
        )

    def get_state_graph(self) -> dict[EngineState, list[str]]:
        """
        Get a representation of the state graph.

        Returns:
            Dictionary mapping states to list of possible next states
        """
        graph: dict[EngineState, list[str]] = {}
        for state in EngineState:
            transitions = self.transitions.get(state, [])
            graph[state] = [f"{t.mutation_name} -> {t.to_state.name}" for t in transitions]
        return graph


class PolymorphicEnginePass(MutationPass):
    """
    Mutation pass that uses the polymorphic engine for iterative mutations.

    Provides a convenient interface to use the polymorphic engine
    as a standard mutation pass.

    Config options:
        - seed: Random seed (default: None)
        - max_iterations: Maximum iterations (default: 10)
        - enable_substitution: Enable instruction substitution (default: True)
        - enable_dead_code: Enable dead code injection (default: True)
        - enable_reordering: Enable block reordering (default: True)
        - enable_flattening: Enable control flow flattening (default: True)
        - enable_virtualization: Enable code virtualization (default: False)
        - enable_string_obfuscation: Enable string obfuscation (default: True)
        - enable_mobility: Enable code mobility (default: False)
        - enable_outlining: Enable function outlining (default: False)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="PolymorphicEngine", config=config)

        self.seed = self.config.get("seed", None)
        self.max_iterations = self.config.get("max_iterations", 10)

        self.enable_substitution = self.config.get("enable_substitution", True)
        self.enable_dead_code = self.config.get("enable_dead_code", True)
        self.enable_reordering = self.config.get("enable_reordering", True)
        self.enable_flattening = self.config.get("enable_flattening", True)
        self.enable_virtualization = self.config.get("enable_virtualization", False)
        self.enable_string_obfuscation = self.config.get("enable_string_obfuscation", True)
        self.enable_mobility = self.config.get("enable_mobility", False)
        self.enable_outlining = self.config.get("enable_outlining", False)

        self.engine = PolymorphicEngine(seed=self.seed)
        self._setup_engine()

        self.set_support(
            formats=("ELF", "PE", "Mach-O"),
            architectures=("x86_64", "x86"),
            validators=("structural", "runtime"),
            stability="experimental",
            notes=(
                "iterative polymorphic transformations",
                "state machine driven mutations",
                "convergence detection",
            ),
        )

    def _setup_engine(self) -> None:
        """Setup default state transitions."""
        state = EngineState.INIT

        if self.enable_substitution:
            self.engine.add_transition(
                EngineState.INIT,
                EngineState.SUBSTITUTED,
                "InstructionSubstitution",
                probability=0.8,
            )
            state = EngineState.SUBSTITUTED

        if self.enable_dead_code:
            from_state = state
            to_state = EngineState.DEAD_CODE_INJECTED
            self.engine.add_transition(
                from_state,
                to_state,
                "DeadCodeInjection",
                probability=0.7,
            )
            state = to_state

        if self.enable_reordering:
            from_state = state
            to_state = EngineState.REORDERED
            self.engine.add_transition(
                from_state,
                to_state,
                "BlockReordering",
                probability=0.6,
            )
            state = to_state

        if self.enable_flattening:
            from_state = state
            to_state = EngineState.FLATTENED
            self.engine.add_transition(
                from_state,
                to_state,
                "ControlFlowFlattening",
                probability=0.5,
            )
            state = to_state

        if self.enable_string_obfuscation:
            from_state = state
            to_state = EngineState.STRING_OBFUSCATED
            self.engine.add_transition(
                from_state,
                to_state,
                "StringObfuscation",
                probability=0.6,
            )
            state = to_state

        if self.enable_virtualization:
            from_state = state
            to_state = EngineState.VIRTUALIZED
            self.engine.add_transition(
                from_state,
                to_state,
                "CodeVirtualization",
                probability=0.3,
            )
            state = to_state

        if self.enable_mobility:
            from_state = state
            to_state = EngineState.MOBILIZED
            self.engine.add_transition(
                from_state,
                to_state,
                "CodeMobility",
                probability=0.4,
            )
            state = to_state

        if self.enable_outlining:
            from_state = state
            to_state = EngineState.OUTLINED
            self.engine.add_transition(
                from_state,
                to_state,
                "FunctionOutlining",
                probability=0.3,
            )
            state = to_state

        self.engine.add_transition(
            state,
            EngineState.FINAL,
            "NoOp",
            probability=1.0,
        )

    def register_mutation(self, name: str, mutation: MutationPass) -> None:
        """
        Register a mutation with the engine.

        Args:
            name: Name to identify the mutation
            mutation: Mutation pass instance
        """
        self.engine.add_mutation(name, mutation)

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply polymorphic engine to binary.

        Args:
            binary: Binary to mutate

        Returns:
            Statistics from engine run
        """
        self._reset_random()
        logger.info("Starting polymorphic engine")

        result = self.engine.run(binary, max_iterations=self.max_iterations)

        mutations_by_name: dict[str, list[MutationResult]] = {}
        for m in result.mutations_applied:
            if m.name not in mutations_by_name:
                mutations_by_name[m.name] = []
            mutations_by_name[m.name].append(m)

        stats = {
            "initial_state": result.initial_state.name,
            "final_state": result.final_state.name,
            "iterations": result.iterations,
            "converged": result.converged,
            "mutations_applied": len(result.mutations_applied),
            "successful_mutations": sum(1 for m in result.mutations_applied if m.success),
            "failed_mutations": sum(1 for m in result.mutations_applied if not m.success),
        }

        for name, mutations in mutations_by_name.items():
            stats[f"{name}_count"] = len(mutations)

        stats.update(result.final_stats)

        logger.info(
            f"Polymorphic engine completed: {stats['successful_mutations']}/{stats['mutations_applied']} "
            f"mutations in {result.iterations} iterations"
        )

        return stats


class NoOpMutation(MutationPass):
    """No-operation mutation pass for state transitions."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="NoOp", config=config)

    def apply(self, binary: Binary) -> dict[str, Any]:
        """Apply no-op mutation."""
        return {"applied": False, "reason": "NoOp mutation"}


class NoOp(MutationPass):
    """No-operation pass for identity transitions."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="NoOp", config=config)

    def apply(self, binary: Binary) -> dict[str, Any]:
        return {"mutations": 0, "reason": "NoOp pass"}
