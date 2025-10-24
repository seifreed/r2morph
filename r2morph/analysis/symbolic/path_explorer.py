"""
Path exploration module for guided symbolic execution.

This module provides intelligent path exploration strategies for
analyzing obfuscated binaries, with special focus on VM handlers
and control flow obfuscation patterns.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable

try:
    import angr
    from angr import SimulationManager
    from angr.exploration_techniques import ExplorationTechnique
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    angr = None
    SimulationManager = None
    ExplorationTechnique = None

logger = logging.getLogger(__name__)


class ExplorationStrategy(Enum):
    """Path exploration strategies for different analysis goals."""
    
    BFS = "breadth_first"           # Breadth-first search
    DFS = "depth_first"             # Depth-first search  
    GUIDED = "guided"               # Guided by heuristics
    VM_HANDLER = "vm_handler"       # Specialized for VM handler analysis
    OPAQUE_PREDICATE = "opaque_predicate"  # Focus on opaque predicate detection


@dataclass
class ExplorationResult:
    """Result of path exploration."""
    
    paths_explored: int = 0
    vm_handlers_found: int = 0
    opaque_predicates_found: int = 0
    interesting_paths: List[Any] = field(default_factory=list)
    execution_time: float = 0.0
    constraints_collected: List[Any] = field(default_factory=list)
    coverage_info: Dict[str, Any] = field(default_factory=dict)


class VMHandlerDetectionTechnique(ExplorationTechnique):
    """
    Exploration technique specialized for VM handler detection.
    
    This technique prioritizes paths that exhibit VM-like behavior:
    - Indirect jumps with computed targets
    - Switch-like instruction dispatching
    - Frequent memory accesses to handler tables
    """
    
    def __init__(self):
        super().__init__()
        self.handler_patterns: Set[int] = set()
        self.switch_tables: Dict[int, List[int]] = {}
        
    def step(self, simgr: Any, stash: str = 'active', **kwargs) -> Any:
        """
        Custom stepping logic for VM handler detection.
        
        Args:
            simgr: Simulation manager
            stash: Stash name
            
        Returns:
            Updated simulation manager
        """
        if not ANGR_AVAILABLE:
            return simgr
            
        # Prioritize states that show VM handler patterns
        if stash in simgr.stashes:
            states = simgr.stashes[stash]
            scored_states = []
            
            for state in states:
                score = self._score_vm_likelihood(state)
                scored_states.append((score, state))
            
            # Sort by VM likelihood score (higher is more likely)
            scored_states.sort(key=lambda x: x[0], reverse=True)
            
            # Keep top N states to prevent state explosion
            max_states = 10
            simgr.stashes[stash] = [state for _, state in scored_states[:max_states]]
        
        return simgr
    
    def _score_vm_likelihood(self, state: Any) -> float:
        """
        Score state based on VM handler likelihood.
        
        Args:
            state: Symbolic state
            
        Returns:
            Score (higher = more likely VM handler)
        """
        score = 0.0
        
        try:
            # Check for indirect jumps
            if state.solver.symbolic(state.regs.rip):
                score += 2.0
            
            # Check for switch-like patterns (high number of successors)
            if hasattr(state, 'history') and state.history.jump_kind == 'Ijk_Boring':
                score += 1.0
            
            # Check for memory access patterns
            if len(state.history.mem_reads.hardcopy) > 5:
                score += 1.5
                
            # Penalize very deep paths (likely not VM handlers)
            if state.history.depth > 50:
                score -= 1.0
                
        except Exception as e:
            logger.debug(f"Error scoring VM likelihood: {e}")
            
        return score


class OpaquePredicateDetectionTechnique(ExplorationTechnique):
    """
    Exploration technique for detecting opaque predicates.
    
    Focuses on identifying branches that always take the same path
    regardless of input values.
    """
    
    def __init__(self):
        super().__init__()
        self.branch_outcomes: Dict[int, List[bool]] = {}
        self.opaque_candidates: Set[int] = set()
        
    def step(self, simgr: Any, stash: str = 'active', **kwargs) -> Any:
        """Custom stepping for opaque predicate detection."""
        if not ANGR_AVAILABLE:
            return simgr
            
        # Track branch outcomes
        if stash in simgr.stashes:
            for state in simgr.stashes[stash]:
                self._track_branch_outcomes(state)
        
        return simgr
    
    def _track_branch_outcomes(self, state: Any):
        """Track outcomes of conditional branches."""
        try:
            if hasattr(state, 'history') and state.history.jump_kind == 'Ijk_Conditional':
                branch_addr = state.history.addr
                
                # Record this branch outcome
                if branch_addr not in self.branch_outcomes:
                    self.branch_outcomes[branch_addr] = []
                    
                # Determine if branch was taken
                taken = state.history.jumpkind == 'Ijk_Conditional'
                self.branch_outcomes[branch_addr].append(taken)
                
                # Check if this looks like an opaque predicate
                outcomes = self.branch_outcomes[branch_addr]
                if len(outcomes) >= 5 and len(set(outcomes)) == 1:
                    self.opaque_candidates.add(branch_addr)
                    logger.info(f"Potential opaque predicate at 0x{branch_addr:x}")
                    
        except Exception as e:
            logger.debug(f"Error tracking branch outcomes: {e}")


class PathExplorer:
    """
    Advanced path exploration engine for symbolic execution.
    
    Provides intelligent path exploration strategies tailored for
    different analysis goals in obfuscated binary analysis.
    """
    
    def __init__(self, angr_bridge):
        """
        Initialize path explorer.
        
        Args:
            angr_bridge: AngrBridge instance
        """
        if not ANGR_AVAILABLE:
            raise ImportError("angr is required for path exploration")
            
        self.angr_bridge = angr_bridge
        self.exploration_techniques: Dict[ExplorationStrategy, Any] = {}
        self._setup_exploration_techniques()
        
    def _setup_exploration_techniques(self):
        """Set up exploration techniques for different strategies."""
        self.exploration_techniques[ExplorationStrategy.VM_HANDLER] = VMHandlerDetectionTechnique()
        self.exploration_techniques[ExplorationStrategy.OPAQUE_PREDICATE] = OpaquePredicateDetectionTechnique()
    
    def explore_function(self, 
                        function_addr: int,
                        strategy: ExplorationStrategy = ExplorationStrategy.GUIDED,
                        max_paths: int = 100,
                        timeout: int = 300,
                        target_addresses: Optional[List[int]] = None) -> ExplorationResult:
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
                    simgr.active = simgr.active[:max_paths // 2]
            
            # Collect results
            result = self._collect_exploration_results(simgr, strategy, time.time() - start_time)
            result.paths_explored = paths_explored
            
            return result
            
        except Exception as e:
            logger.error(f"Path exploration failed: {e}")
            return ExplorationResult(execution_time=time.time() - start_time)
    
    def _collect_exploration_results(self, 
                                   simgr: Any, 
                                   strategy: ExplorationStrategy,
                                   execution_time: float) -> ExplorationResult:
        """
        Collect and analyze results from path exploration.
        
        Args:
            simgr: Simulation manager
            strategy: Exploration strategy used
            execution_time: Time spent exploring
            
        Returns:
            ExplorationResult with analysis
        """
        result = ExplorationResult(execution_time=execution_time)
        
        # Collect interesting states
        interesting_states = []
        if hasattr(simgr, 'found'):
            interesting_states.extend(simgr.found)
        if hasattr(simgr, 'deadended'):
            interesting_states.extend(simgr.deadended)
        
        result.interesting_paths = interesting_states
        
        # Strategy-specific result collection
        if strategy == ExplorationStrategy.VM_HANDLER:
            technique = self.exploration_techniques[strategy]
            if isinstance(technique, VMHandlerDetectionTechnique):
                result.vm_handlers_found = len(technique.handler_patterns)
                
        elif strategy == ExplorationStrategy.OPAQUE_PREDICATE:
            technique = self.exploration_techniques[strategy]
            if isinstance(technique, OpaquePredicateDetectionTechnique):
                result.opaque_predicates_found = len(technique.opaque_candidates)
        
        # Collect constraints from all states
        constraints = []
        for state in interesting_states:
            try:
                if hasattr(state, 'solver'):
                    constraints.extend(state.solver.constraints)
            except Exception as e:
                logger.debug(f"Error collecting constraints: {e}")
        
        result.constraints_collected = constraints
        
        return result
    
    def find_vm_handlers(self, 
                        dispatcher_addr: int,
                        max_handlers: int = 50) -> List[Dict[str, Any]]:
        """
        Specialized function to find VM handlers from a dispatcher.
        
        Args:
            dispatcher_addr: Address of VM dispatcher function
            max_handlers: Maximum number of handlers to find
            
        Returns:
            List of VM handler information
        """
        logger.info(f"Searching for VM handlers from dispatcher at 0x{dispatcher_addr:x}")
        
        result = self.explore_function(
            dispatcher_addr,
            strategy=ExplorationStrategy.VM_HANDLER,
            max_paths=max_handlers * 2
        )
        
        handlers = []
        technique = self.exploration_techniques[ExplorationStrategy.VM_HANDLER]
        
        if isinstance(technique, VMHandlerDetectionTechnique):
            for handler_addr in technique.handler_patterns:
                handlers.append({
                    "address": handler_addr,
                    "type": "unknown",  # Will be determined by further analysis
                    "confidence": 0.8,  # Based on detection heuristics
                })
        
        logger.info(f"Found {len(handlers)} potential VM handlers")
        return handlers
    
    def detect_opaque_predicates(self, function_addr: int) -> List[Dict[str, Any]]:
        """
        Detect opaque predicates in a function.
        
        Args:
            function_addr: Function address
            
        Returns:
            List of opaque predicate information
        """
        logger.info(f"Detecting opaque predicates in function at 0x{function_addr:x}")
        
        result = self.explore_function(
            function_addr,
            strategy=ExplorationStrategy.OPAQUE_PREDICATE,
            max_paths=200
        )
        
        predicates = []
        technique = self.exploration_techniques[ExplorationStrategy.OPAQUE_PREDICATE]
        
        if isinstance(technique, OpaquePredicateDetectionTechnique):
            for predicate_addr in technique.opaque_candidates:
                outcomes = technique.branch_outcomes.get(predicate_addr, [])
                predicates.append({
                    "address": predicate_addr,
                    "always_taken": all(outcomes) if outcomes else None,
                    "sample_count": len(outcomes),
                    "confidence": min(1.0, len(outcomes) / 10.0),
                })
        
        logger.info(f"Found {len(predicates)} potential opaque predicates")
        return predicates