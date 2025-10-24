"""
State management for symbolic execution.

This module provides efficient management of symbolic execution states,
including state pruning, merging, and scheduling strategies optimized
for analyzing obfuscated binaries.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable
import time
import heapq

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    angr = None

logger = logging.getLogger(__name__)


class StateSchedulingStrategy(Enum):
    """Strategies for scheduling state exploration."""
    
    RANDOM = "random"
    DEPTH_FIRST = "depth_first"
    BREADTH_FIRST = "breadth_first"
    COVERAGE_GUIDED = "coverage_guided"
    PRIORITY_BASED = "priority_based"


@dataclass
class StateMetrics:
    """Metrics for evaluating state quality."""
    
    depth: int = 0
    coverage_new_blocks: int = 0
    constraint_complexity: float = 0.0
    vm_likelihood_score: float = 0.0
    last_access_time: float = field(default_factory=time.time)
    priority_score: float = 0.0


class StateManager:
    """
    Advanced state manager for symbolic execution.
    
    Provides intelligent state management including:
    - State prioritization and scheduling
    - Memory-efficient state storage
    - State merging for equivalent states
    - Adaptive state pruning
    """
    
    def __init__(self, 
                 max_states: int = 100,
                 max_depth: int = 1000,
                 scheduling_strategy: StateSchedulingStrategy = StateSchedulingStrategy.PRIORITY_BASED):
        """
        Initialize state manager.
        
        Args:
            max_states: Maximum number of active states
            max_depth: Maximum exploration depth
            scheduling_strategy: State scheduling strategy
        """
        if not ANGR_AVAILABLE:
            logger.warning("angr not available, state management will be limited")
            
        self.max_states = max_states
        self.max_depth = max_depth
        self.scheduling_strategy = scheduling_strategy
        
        # State storage
        self.active_states: Dict[int, Any] = {}
        self.state_metrics: Dict[int, StateMetrics] = {}
        self.state_priority_queue: List[tuple] = []  # (priority, state_id)
        
        # Coverage tracking
        self.global_coverage: Set[int] = set()
        self.state_coverage: Dict[int, Set[int]] = {}
        
        # Performance metrics
        self.states_created = 0
        self.states_pruned = 0
        self.states_merged = 0
        
    def add_state(self, state: Any, priority: float = 0.0) -> int:
        """
        Add a new state to management.
        
        Args:
            state: Symbolic state
            priority: Initial priority score
            
        Returns:
            State ID
        """
        if not ANGR_AVAILABLE:
            return -1
            
        state_id = self.states_created
        self.states_created += 1
        
        # Store state and initialize metrics
        self.active_states[state_id] = state
        self.state_metrics[state_id] = StateMetrics(
            depth=self._get_state_depth(state),
            priority_score=priority
        )
        self.state_coverage[state_id] = set()
        
        # Add to priority queue
        heapq.heappush(self.state_priority_queue, (-priority, state_id))
        
        # Enforce state limit
        if len(self.active_states) > self.max_states:
            self._prune_states()
            
        logger.debug(f"Added state {state_id} with priority {priority}")
        return state_id
    
    def get_next_state(self) -> Optional[tuple[int, Any]]:
        """
        Get next state for execution based on scheduling strategy.
        
        Returns:
            Tuple of (state_id, state) or None if no states available
        """
        if not self.state_priority_queue:
            return None
            
        if self.scheduling_strategy == StateSchedulingStrategy.PRIORITY_BASED:
            return self._get_highest_priority_state()
        elif self.scheduling_strategy == StateSchedulingStrategy.COVERAGE_GUIDED:
            return self._get_best_coverage_state()
        elif self.scheduling_strategy == StateSchedulingStrategy.DEPTH_FIRST:
            return self._get_deepest_state()
        elif self.scheduling_strategy == StateSchedulingStrategy.BREADTH_FIRST:
            return self._get_shallowest_state()
        else:
            return self._get_random_state()
    
    def _get_highest_priority_state(self) -> Optional[tuple[int, Any]]:
        """Get state with highest priority."""
        while self.state_priority_queue:
            neg_priority, state_id = heapq.heappop(self.state_priority_queue)
            
            if state_id in self.active_states:
                state = self.active_states[state_id]
                return state_id, state
                
        return None
    
    def _get_best_coverage_state(self) -> Optional[tuple[int, Any]]:
        """Get state that is likely to increase coverage."""
        best_state_id = None
        best_score = -1
        
        for state_id in self.active_states:
            metrics = self.state_metrics[state_id]
            # Prioritize states that have found new basic blocks recently
            score = metrics.coverage_new_blocks - (metrics.depth * 0.1)
            
            if score > best_score:
                best_score = score
                best_state_id = state_id
        
        if best_state_id is not None:
            state = self.active_states[best_state_id]
            return best_state_id, state
            
        return None
    
    def _get_deepest_state(self) -> Optional[tuple[int, Any]]:
        """Get deepest state for depth-first exploration."""
        deepest_id = None
        max_depth = -1
        
        for state_id in self.active_states:
            depth = self.state_metrics[state_id].depth
            if depth > max_depth:
                max_depth = depth
                deepest_id = state_id
        
        if deepest_id is not None:
            return deepest_id, self.active_states[deepest_id]
        return None
    
    def _get_shallowest_state(self) -> Optional[tuple[int, Any]]:
        """Get shallowest state for breadth-first exploration."""
        shallowest_id = None
        min_depth = float('inf')
        
        for state_id in self.active_states:
            depth = self.state_metrics[state_id].depth
            if depth < min_depth:
                min_depth = depth
                shallowest_id = state_id
        
        if shallowest_id is not None:
            return shallowest_id, self.active_states[shallowest_id]
        return None
    
    def _get_random_state(self) -> Optional[tuple[int, Any]]:
        """Get random state."""
        import random
        
        if self.active_states:
            state_id = random.choice(list(self.active_states.keys()))
            return state_id, self.active_states[state_id]
        return None
    
    def update_state_coverage(self, state_id: int, new_blocks: Set[int]):
        """
        Update coverage information for a state.
        
        Args:
            state_id: State identifier
            new_blocks: Set of newly covered basic blocks
        """
        if state_id not in self.state_coverage:
            return
            
        # Track new blocks for this state
        state_coverage = self.state_coverage[state_id]
        truly_new_blocks = new_blocks - self.global_coverage
        
        # Update global and state coverage
        self.global_coverage.update(new_blocks)
        state_coverage.update(new_blocks)
        
        # Update metrics
        if state_id in self.state_metrics:
            self.state_metrics[state_id].coverage_new_blocks = len(truly_new_blocks)
            
        logger.debug(f"State {state_id} found {len(truly_new_blocks)} new blocks")
    
    def update_state_priority(self, state_id: int, new_priority: float):
        """
        Update priority of a state.
        
        Args:
            state_id: State identifier
            new_priority: New priority score
        """
        if state_id in self.state_metrics:
            self.state_metrics[state_id].priority_score = new_priority
            # Re-add to priority queue
            heapq.heappush(self.state_priority_queue, (-new_priority, state_id))
    
    def _prune_states(self):
        """Prune least promising states to maintain state limit."""
        if len(self.active_states) <= self.max_states:
            return
            
        # Sort states by pruning criteria
        states_to_evaluate = []
        
        for state_id, metrics in self.state_metrics.items():
            if state_id in self.active_states:
                # Calculate pruning score (lower = more likely to be pruned)
                pruning_score = self._calculate_pruning_score(metrics)
                states_to_evaluate.append((pruning_score, state_id))
        
        # Sort by pruning score (ascending)
        states_to_evaluate.sort()
        
        # Prune worst states
        states_to_prune = len(self.active_states) - self.max_states
        for i in range(states_to_prune):
            if i < len(states_to_evaluate):
                _, state_id = states_to_evaluate[i]
                self._remove_state(state_id)
                self.states_pruned += 1
                
        logger.debug(f"Pruned {states_to_prune} states")
    
    def _calculate_pruning_score(self, metrics: StateMetrics) -> float:
        """
        Calculate score for state pruning (lower = more likely to prune).
        
        Args:
            metrics: State metrics
            
        Returns:
            Pruning score
        """
        score = 0.0
        
        # Reward recent coverage discovery
        score += metrics.coverage_new_blocks * 10.0
        
        # Reward higher VM likelihood
        score += metrics.vm_likelihood_score * 5.0
        
        # Penalize excessive depth
        if metrics.depth > self.max_depth * 0.8:
            score -= (metrics.depth - self.max_depth * 0.8) * 2.0
        
        # Penalize high constraint complexity
        score -= metrics.constraint_complexity * 0.1
        
        # Penalize old states (haven't been accessed recently)
        age = time.time() - metrics.last_access_time
        score -= age * 0.01
        
        return score
    
    def _remove_state(self, state_id: int):
        """Remove state from all tracking structures."""
        if state_id in self.active_states:
            del self.active_states[state_id]
        if state_id in self.state_metrics:
            del self.state_metrics[state_id]
        if state_id in self.state_coverage:
            del self.state_coverage[state_id]
    
    def _get_state_depth(self, state: Any) -> int:
        """Get exploration depth of a state."""
        if ANGR_AVAILABLE and hasattr(state, 'history'):
            return state.history.depth
        return 0
    
    def merge_equivalent_states(self) -> int:
        """
        Merge states that are equivalent at the same program point.
        
        Returns:
            Number of states merged
        """
        if not ANGR_AVAILABLE:
            return 0
            
        # Group states by program counter
        pc_groups: Dict[int, List[int]] = {}
        
        for state_id, state in self.active_states.items():
            try:
                pc = state.addr
                if pc not in pc_groups:
                    pc_groups[pc] = []
                pc_groups[pc].append(state_id)
            except Exception:
                continue
        
        merged_count = 0
        
        # For each program point with multiple states, try to merge
        for pc, state_ids in pc_groups.items():
            if len(state_ids) > 1:
                merged = self._try_merge_states_at_pc(state_ids)
                merged_count += merged
        
        self.states_merged += merged_count
        return merged_count
    
    def _try_merge_states_at_pc(self, state_ids: List[int]) -> int:
        """
        Try to merge states at the same program counter.
        
        Args:
            state_ids: List of state IDs at same PC
            
        Returns:
            Number of states successfully merged
        """
        # Simplified merging - in practice would need sophisticated
        # analysis to determine if states can be safely merged
        
        if len(state_ids) <= 1:
            return 0
            
        # Keep the state with best metrics, remove others
        best_state_id = state_ids[0]
        best_score = self._calculate_pruning_score(self.state_metrics[best_state_id])
        
        for state_id in state_ids[1:]:
            score = self._calculate_pruning_score(self.state_metrics[state_id])
            if score > best_score:
                best_score = score
                best_state_id = state_id
        
        # Remove all but best state
        merged_count = 0
        for state_id in state_ids:
            if state_id != best_state_id:
                self._remove_state(state_id)
                merged_count += 1
        
        return merged_count
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get state management statistics."""
        return {
            "active_states": len(self.active_states),
            "total_coverage": len(self.global_coverage),
            "states_created": self.states_created,
            "states_pruned": self.states_pruned,
            "states_merged": self.states_merged,
            "max_depth": max((m.depth for m in self.state_metrics.values()), default=0),
            "avg_priority": sum(m.priority_score for m in self.state_metrics.values()) / max(len(self.state_metrics), 1),
        }
    
    def cleanup(self):
        """Clean up state manager resources."""
        self.active_states.clear()
        self.state_metrics.clear()
        self.state_coverage.clear()
        self.state_priority_queue.clear()
        self.global_coverage.clear()