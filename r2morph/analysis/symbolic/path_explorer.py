"""Path exploration module for guided symbolic execution."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import angr
else:
    try:
        import angr
    except ImportError:
        angr = None

from r2morph.analysis.symbolic.path_explorer_models import ExplorationResult, ExplorationStrategy
from r2morph.analysis.symbolic.path_explorer_results import (
    build_opaque_predicates as _build_opaque_predicates,
)
from r2morph.analysis.symbolic.path_explorer_results import (
    build_vm_handlers as _build_vm_handlers,
)
from r2morph.analysis.symbolic.path_explorer_results import (
    collect_exploration_results as _collect_exploration_results,
)
from r2morph.analysis.symbolic.path_explorer_techniques import (
    OpaquePredicateDetectionTechnique,
    VMHandlerDetectionTechnique,
)

ANGR_AVAILABLE = angr is not None

logger = logging.getLogger(__name__)


class PathExplorer:
    """
    Advanced path exploration engine for symbolic execution.

    Provides intelligent path exploration strategies tailored for
    different analysis goals in obfuscated binary analysis.
    """

    def __init__(self, angr_bridge: Any) -> None:
        """
        Initialize path explorer.

        Args:
            angr_bridge: AngrBridge instance
        """
        if not ANGR_AVAILABLE:
            raise ImportError("angr is required for path exploration")

        self.angr_bridge = angr_bridge
        self.exploration_techniques: dict[ExplorationStrategy, Any] = {}
        self._setup_exploration_techniques()

    def _setup_exploration_techniques(self) -> None:
        """Set up exploration techniques for different strategies."""
        self.exploration_techniques[ExplorationStrategy.VM_HANDLER] = VMHandlerDetectionTechnique()
        self.exploration_techniques[ExplorationStrategy.OPAQUE_PREDICATE] = OpaquePredicateDetectionTechnique()

    def explore_function(
        self,
        function_addr: int,
        strategy: ExplorationStrategy = ExplorationStrategy.GUIDED,
        max_paths: int = 100,
        timeout: int = 300,
        target_addresses: list[int] | None = None,
    ) -> ExplorationResult:
        """
        Explore paths in a function using specified strategy.

        Args:
            function_addr: Function address to explore
            strategy: Exploration strategy
            max_paths: Maximum number of paths to explore
            timeout: Timeout in seconds
            target_addresses: Specific addresses to reach

        Returns:
            ExplorationResult with findings
        """
        import time

        start_time = time.time()

        try:
            # Create initial symbolic state
            initial_state = self.angr_bridge.create_symbolic_state(function_addr)
            if not initial_state:
                logger.error("Failed to create initial symbolic state")
                return ExplorationResult()

            # Create simulation manager
            simgr = self.angr_bridge.angr_project.factory.simulation_manager(initial_state)

            # Apply exploration technique
            if strategy in self.exploration_techniques:
                technique = self.exploration_techniques[strategy]
                simgr.use_technique(technique)

            # Set up targets if specified
            if target_addresses:
                simgr.use_technique(angr.exploration_techniques.Explorer(find=target_addresses))

            # Explore paths
            paths_explored = 0
            while simgr.active and paths_explored < max_paths:
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    logger.warning(f"Path exploration timed out after {elapsed:.1f}s")
                    break

                simgr.step()
                paths_explored += len(simgr.active)

                # Prune states to prevent explosion
                if len(simgr.active) > max_paths // 2:
                    # Keep most promising states
                    simgr.active = simgr.active[: max_paths // 2]

            # Collect results
            result = self._collect_exploration_results(simgr, strategy, time.time() - start_time)
            result.paths_explored = paths_explored

            return result

        except Exception as e:
            logger.error(f"Path exploration failed: {e}")
            return ExplorationResult(execution_time=time.time() - start_time)

    def _collect_exploration_results(
        self, simgr: Any, strategy: ExplorationStrategy, execution_time: float
    ) -> ExplorationResult:
        """Collect and analyze results from path exploration."""
        return _collect_exploration_results(simgr, strategy, execution_time, self.exploration_techniques)

    def find_vm_handlers(self, dispatcher_addr: int, max_handlers: int = 50) -> list[dict[str, Any]]:
        """
        Specialized function to find VM handlers from a dispatcher.

        Args:
            dispatcher_addr: Address of VM dispatcher function
            max_handlers: Maximum number of handlers to find

        Returns:
            List of VM handler information
        """
        logger.info(f"Searching for VM handlers from dispatcher at 0x{dispatcher_addr:x}")

        self.explore_function(dispatcher_addr, strategy=ExplorationStrategy.VM_HANDLER, max_paths=max_handlers * 2)

        technique = self.exploration_techniques[ExplorationStrategy.VM_HANDLER]
        handlers = _build_vm_handlers(technique)

        logger.info(f"Found {len(handlers)} potential VM handlers")
        return handlers

    def detect_opaque_predicates(self, function_addr: int) -> list[dict[str, Any]]:
        """
        Detect opaque predicates in a function.

        Args:
            function_addr: Function address

        Returns:
            List of opaque predicate information
        """
        logger.info(f"Detecting opaque predicates in function at 0x{function_addr:x}")

        self.explore_function(function_addr, strategy=ExplorationStrategy.OPAQUE_PREDICATE, max_paths=200)

        technique = self.exploration_techniques[ExplorationStrategy.OPAQUE_PREDICATE]
        predicates = _build_opaque_predicates(technique)

        logger.info(f"Found {len(predicates)} potential opaque predicates")
        return predicates
