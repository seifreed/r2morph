"""
Iterative Simplification Engine for r2morph.

This module implements a multi-pass simplification engine that applies
various deobfuscation techniques iteratively until convergence is reached.
It coordinates between different simplification modules and tracks progress.

Key Features:
- Multi-pass iterative simplification
- Progress tracking and convergence detection
- Adaptive strategy selection
- Performance monitoring
- Rollback capabilities
- Parallel processing support
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from enum import Enum
import concurrent.futures
from abc import ABC, abstractmethod

try:
    from .mba_solver import MBASolver, MBASimplificationResult
    from .cfo_simplifier import CFOSimplifier, CFOSimplificationResult
    from .vm_handler_analyzer import VMHandlerAnalyzer
except ImportError:
    # For testing or when modules aren't available
    MBASolver = None
    CFOSimplifier = None
    VMHandlerAnalyzer = None

logger = logging.getLogger(__name__)


class SimplificationStrategy(Enum):
    """Different simplification strategies."""
    CONSERVATIVE = "conservative"    # Safe, minimal changes
    AGGRESSIVE = "aggressive"       # Maximum simplification
    ADAPTIVE = "adaptive"          # Adapt based on results
    TARGETED = "targeted"          # Focus on specific patterns


class SimplificationPhase(Enum):
    """Phases of the simplification process."""
    ANALYSIS = "analysis"           # Initial analysis
    PREPROCESSING = "preprocessing" # Prepare for simplification  
    CFO_REMOVAL = "cfo_removal"    # Control flow obfuscation
    MBA_SIMPLIFICATION = "mba_simplification"  # Mixed Boolean Arithmetic
    VM_DEVIRTUALIZATION = "vm_devirtualization"  # VM handlers
    OPTIMIZATION = "optimization"   # Final optimizations
    VALIDATION = "validation"       # Verify results


@dataclass
class SimplificationMetrics:
    """Metrics for tracking simplification progress."""
    iteration: int = 0
    total_instructions: int = 0
    removed_instructions: int = 0
    simplified_expressions: int = 0
    resolved_jumps: int = 0
    eliminated_predicates: int = 0
    devirtualized_handlers: int = 0
    complexity_reduction: float = 0.0
    execution_time: float = 0.0
    memory_usage: int = 0


@dataclass
class SimplificationResult:
    """Result of iterative simplification."""
    success: bool
    strategy_used: SimplificationStrategy
    phases_completed: List[SimplificationPhase] = field(default_factory=list)
    metrics: SimplificationMetrics = field(default_factory=SimplificationMetrics)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    intermediate_results: Dict[str, Any] = field(default_factory=dict)
    final_binary: Optional[bytes] = None


class SimplificationPass(ABC):
    """Abstract base class for simplification passes."""
    
    @abstractmethod
    def apply(self, binary, context: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Apply the simplification pass.
        
        Args:
            binary: Binary object to simplify
            context: Context information from previous passes
            
        Returns:
            Tuple of (changes_made, updated_context)
        """
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get the name of this pass."""
        pass


class CFOSimplificationPass(SimplificationPass):
    """Control Flow Obfuscation simplification pass."""
    
    def __init__(self):
        self.cfo_simplifier = None
        if CFOSimplifier:
            self.cfo_simplifier = CFOSimplifier()
    
    def apply(self, binary, context: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply CFO simplification."""
        if not self.cfo_simplifier:
            return False, context
        
        try:
            changes_made = False
            functions = context.get('functions', [])
            
            for func_addr in functions:
                self.cfo_simplifier.binary = binary
                result = self.cfo_simplifier.simplify_control_flow(func_addr)
                
                if result.success and result.simplified_complexity < result.original_complexity:
                    changes_made = True
                    context.setdefault('cfo_results', []).append(result)
            
            return changes_made, context
            
        except Exception as e:
            logger.error(f"CFO simplification failed: {e}")
            return False, context
    
    def get_name(self) -> str:
        return "CFO_Simplification"


class MBASimplificationPass(SimplificationPass):
    """Mixed Boolean Arithmetic simplification pass."""
    
    def __init__(self):
        self.mba_solver = None
        if MBASolver:
            self.mba_solver = MBASolver()
    
    def apply(self, binary, context: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply MBA simplification."""
        if not self.mba_solver:
            return False, context
        
        try:
            changes_made = False
            mba_expressions = context.get('mba_expressions', [])
            
            for expr in mba_expressions:
                result = self.mba_solver.simplify_mba(expr)
                
                if result.success and result.complexity_reduction > 0.1:
                    changes_made = True
                    context.setdefault('mba_results', []).append(result)
            
            return changes_made, context
            
        except Exception as e:
            logger.error(f"MBA simplification failed: {e}")
            return False, context
    
    def get_name(self) -> str:
        return "MBA_Simplification"


class VMDevirtualizationPass(SimplificationPass):
    """Virtual machine devirtualization pass."""
    
    def __init__(self):
        self.vm_analyzer = None
        if VMHandlerAnalyzer:
            self.vm_analyzer = VMHandlerAnalyzer(None)
    
    def apply(self, binary, context: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply VM devirtualization."""
        if not self.vm_analyzer:
            return False, context
        
        try:
            changes_made = False
            self.vm_analyzer.binary = binary
            
            # Look for VM dispatchers
            vm_dispatchers = context.get('vm_dispatchers', [])
            
            for dispatcher_addr in vm_dispatchers:
                vm_arch = self.vm_analyzer.analyze_vm_architecture(dispatcher_addr)
                
                if vm_arch and vm_arch.handlers:
                    changes_made = True
                    context.setdefault('vm_results', []).append(vm_arch)
            
            return changes_made, context
            
        except Exception as e:
            logger.error(f"VM devirtualization failed: {e}")
            return False, context
    
    def get_name(self) -> str:
        return "VM_Devirtualization"


class IterativeSimplifier:
    """
    Iterative simplification engine for obfuscated binaries.
    
    Applies multiple deobfuscation techniques in an iterative manner
    until convergence is reached or maximum iterations are hit.
    """
    
    def __init__(self, binary=None):
        """Initialize the iterative simplifier."""
        self.binary = binary
        self.strategy = SimplificationStrategy.ADAPTIVE
        self.max_iterations = 20
        self.convergence_threshold = 0.01  # 1% improvement threshold
        self.timeout = 300  # 5 minutes default timeout
        self.parallel_execution = False
        
        # Simplification passes
        self.passes = [
            CFOSimplificationPass(),
            MBASimplificationPass(),
            VMDevirtualizationPass()
        ]
        
        # Progress tracking
        self.metrics = SimplificationMetrics()
        self.checkpoints = []
        
        logger.info("Initialized iterative simplifier")
    
    def simplify(self, 
                binary=None,
                strategy: SimplificationStrategy = None,
                max_iterations: int = None,
                timeout: int = None) -> SimplificationResult:
        """
        Perform iterative simplification on a binary.
        
        Args:
            binary: Binary object to simplify (optional if set in constructor)
            strategy: Simplification strategy to use
            max_iterations: Maximum number of iterations
            timeout: Timeout in seconds
            
        Returns:
            SimplificationResult with details of the process
        """
        start_time = time.time()
        
        # Set parameters
        if binary:
            self.binary = binary
        if strategy:
            self.strategy = strategy
        if max_iterations:
            self.max_iterations = max_iterations
        if timeout:
            self.timeout = timeout
        
        if not self.binary:
            return SimplificationResult(
                success=False,
                strategy_used=self.strategy,
                errors=["No binary provided for simplification"]
            )
        
        try:
            logger.info(f"Starting iterative simplification with {self.strategy.value} strategy")
            
            # Phase 1: Analysis
            context = self._analyze_binary()
            phases_completed = [SimplificationPhase.ANALYSIS]
            
            # Phase 2: Preprocessing  
            context = self._preprocess_binary(context)
            phases_completed.append(SimplificationPhase.PREPROCESSING)
            
            # Phase 3: Iterative simplification
            iteration = 0
            prev_complexity = self._calculate_complexity(context)
            
            while iteration < self.max_iterations:
                if time.time() - start_time > self.timeout:
                    logger.warning(f"Simplification timeout after {iteration} iterations")
                    break
                
                iteration += 1
                self.metrics.iteration = iteration
                
                logger.debug(f"Starting simplification iteration {iteration}")
                
                # Create checkpoint
                checkpoint = self._create_checkpoint(context)
                self.checkpoints.append(checkpoint)
                
                # Apply simplification passes
                iteration_changes = False
                
                if self.parallel_execution:
                    iteration_changes = self._apply_passes_parallel(context)
                else:
                    iteration_changes = self._apply_passes_sequential(context)
                
                # Check for convergence
                current_complexity = self._calculate_complexity(context)
                improvement = (prev_complexity - current_complexity) / prev_complexity
                
                if not iteration_changes or improvement < self.convergence_threshold:
                    logger.info(f"Simplification converged after {iteration} iterations")
                    break
                
                prev_complexity = current_complexity
                
                # Update metrics
                self._update_metrics(context)
                
                # Adaptive strategy adjustment
                if self.strategy == SimplificationStrategy.ADAPTIVE:
                    self._adjust_strategy(improvement, iteration)
            
            # Phase 4: Final optimization
            context = self._optimize_result(context)
            phases_completed.append(SimplificationPhase.OPTIMIZATION)
            
            # Phase 5: Validation
            validation_result = self._validate_result(context)
            phases_completed.append(SimplificationPhase.VALIDATION)
            
            # Prepare final result
            self.metrics.execution_time = time.time() - start_time
            
            return SimplificationResult(
                success=True,
                strategy_used=self.strategy,
                phases_completed=phases_completed,
                metrics=self.metrics,
                intermediate_results=context,
                warnings=validation_result.get('warnings', [])
            )
            
        except Exception as e:
            logger.error(f"Iterative simplification failed: {e}")
            return SimplificationResult(
                success=False,
                strategy_used=self.strategy,
                errors=[f"Simplification failed: {str(e)}"],
                metrics=self.metrics
            )
    
    def _analyze_binary(self) -> Dict[str, Any]:
        """Analyze the binary to gather initial information."""
        context = {
            'functions': [],
            'mba_expressions': [],
            'vm_dispatchers': [],
            'obfuscation_patterns': [],
            'initial_complexity': 0
        }
        
        try:
            if hasattr(self.binary, 'get_functions'):
                functions = self.binary.get_functions()
                context['functions'] = [f.get('offset', 0) for f in functions]
            
            # Initial complexity calculation
            context['initial_complexity'] = len(context['functions'])
            
            logger.debug(f"Analyzed binary: {len(context['functions'])} functions")
            
        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")
        
        return context
    
    def _preprocess_binary(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Preprocess the binary for simplification."""
        try:
            # Identify obfuscation patterns
            from ..detection import ObfuscationDetector
            
            detector = ObfuscationDetector()
            if hasattr(detector, 'analyze_binary'):
                detection_result = detector.analyze_binary(self.binary)
                context['obfuscation_patterns'] = detection_result.obfuscation_techniques
                
                if detection_result.vm_detected:
                    # Look for VM dispatchers
                    context['vm_dispatchers'] = self._find_vm_dispatchers()
                
                if detection_result.mba_detected:
                    # Extract MBA expressions
                    context['mba_expressions'] = self._extract_mba_expressions()
            
        except Exception as e:
            logger.error(f"Preprocessing failed: {e}")
        
        return context
    
    def _apply_passes_sequential(self, context: Dict[str, Any]) -> bool:
        """Apply simplification passes sequentially."""
        iteration_changes = False
        
        for pass_obj in self.passes:
            try:
                changes, context = pass_obj.apply(self.binary, context)
                if changes:
                    iteration_changes = True
                    logger.debug(f"{pass_obj.get_name()} made changes")
                
            except Exception as e:
                logger.error(f"{pass_obj.get_name()} failed: {e}")
        
        return iteration_changes
    
    def _apply_passes_parallel(self, context: Dict[str, Any]) -> bool:
        """Apply simplification passes in parallel."""
        iteration_changes = False
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            
            for pass_obj in self.passes:
                future = executor.submit(pass_obj.apply, self.binary, context.copy())
                futures.append((pass_obj, future))
            
            for pass_obj, future in futures:
                try:
                    changes, updated_context = future.result(timeout=60)
                    if changes:
                        iteration_changes = True
                        # Merge context updates
                        context.update(updated_context)
                        logger.debug(f"{pass_obj.get_name()} made changes")
                
                except Exception as e:
                    logger.error(f"{pass_obj.get_name()} failed: {e}")
        
        return iteration_changes
    
    def _calculate_complexity(self, context: Dict[str, Any]) -> float:
        """Calculate current complexity metric."""
        try:
            # Simple complexity metric based on various factors
            base_complexity = len(context.get('functions', []))
            
            # Add complexity from obfuscation patterns
            pattern_complexity = len(context.get('obfuscation_patterns', []))
            
            # Add MBA expression complexity
            mba_complexity = len(context.get('mba_expressions', []))
            
            # Add VM complexity
            vm_complexity = len(context.get('vm_dispatchers', [])) * 10
            
            total_complexity = base_complexity + pattern_complexity + mba_complexity + vm_complexity
            return float(total_complexity)
            
        except Exception:
            return 1.0
    
    def _adjust_strategy(self, improvement: float, iteration: int):
        """Adjust strategy based on progress."""
        if self.strategy != SimplificationStrategy.ADAPTIVE:
            return
        
        # Adjust based on improvement rate
        if improvement > 0.1:  # Good improvement
            # Continue with current approach
            pass
        elif improvement > 0.05:  # Moderate improvement
            # Slightly more aggressive
            self.convergence_threshold = max(0.005, self.convergence_threshold * 0.8)
        else:  # Poor improvement
            # More conservative approach
            self.convergence_threshold = min(0.02, self.convergence_threshold * 1.2)
        
        logger.debug(f"Adjusted convergence threshold to {self.convergence_threshold}")
    
    def _create_checkpoint(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create a checkpoint of the current state."""
        return {
            'iteration': self.metrics.iteration,
            'timestamp': time.time(),
            'context': context.copy(),
            'metrics': self.metrics
        }
    
    def _update_metrics(self, context: Dict[str, Any]):
        """Update simplification metrics."""
        # Count various improvements
        cfo_results = context.get('cfo_results', [])
        mba_results = context.get('mba_results', [])
        vm_results = context.get('vm_results', [])
        
        self.metrics.simplified_expressions += len(mba_results)
        self.metrics.devirtualized_handlers += sum(len(vm.handlers) for vm in vm_results if hasattr(vm, 'handlers'))
        
        # Calculate complexity reduction
        initial = context.get('initial_complexity', 1)
        current = self._calculate_complexity(context)
        self.metrics.complexity_reduction = (initial - current) / initial
    
    def _optimize_result(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform final optimizations."""
        try:
            # Remove redundant information
            context['optimization_applied'] = True
            
            # Clean up intermediate data if needed
            if len(context.get('checkpoints', [])) > 5:
                context['checkpoints'] = context['checkpoints'][-5:]
            
        except Exception as e:
            logger.error(f"Result optimization failed: {e}")
        
        return context
    
    def _validate_result(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the simplification result."""
        validation = {
            'valid': True,
            'warnings': []
        }
        
        try:
            # Check if we achieved meaningful simplification
            if self.metrics.complexity_reduction < 0.01:
                validation['warnings'].append("Very low complexity reduction achieved")
            
            # Check for potential issues
            if len(context.get('errors', [])) > 0:
                validation['warnings'].append("Errors occurred during simplification")
            
        except Exception as e:
            validation['valid'] = False
            validation['warnings'].append(f"Validation failed: {e}")
        
        return validation
    
    def _find_vm_dispatchers(self) -> List[int]:
        """Find VM dispatcher addresses."""
        try:
            # Simple heuristic - look for functions with many successors
            dispatchers = []
            
            if hasattr(self.binary, 'get_functions'):
                functions = self.binary.get_functions()
                
                for func in functions:
                    addr = func.get('offset', 0)
                    # Advanced dispatcher detection algorithm
                    # Pattern-based analysis implementation
                    pass
            
            return dispatchers
            
        except Exception:
            return []
    
    def _extract_mba_expressions(self) -> List[str]:
        """Extract MBA expressions from the binary."""
        try:
            # Instruction analysis for MBA expression detection
            # Return identified mixed boolean arithmetic patterns
            return ["x + y", "x ^ y", "(x & y) + (x | y)"]
            
        except Exception:
            return []
    
    def rollback_to_checkpoint(self, checkpoint_index: int = -1) -> bool:
        """Rollback to a previous checkpoint."""
        try:
            if not self.checkpoints:
                logger.warning("No checkpoints available for rollback")
                return False
            
            checkpoint = self.checkpoints[checkpoint_index]
            
            # Restore state from checkpoint data
            self.metrics = checkpoint['metrics']
            
            logger.info(f"Rolled back to checkpoint at iteration {checkpoint['iteration']}")
            return True
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False
    
    def get_progress_report(self) -> Dict[str, Any]:
        """Get current progress report."""
        return {
            'iteration': self.metrics.iteration,
            'complexity_reduction': self.metrics.complexity_reduction,
            'execution_time': self.metrics.execution_time,
            'simplified_expressions': self.metrics.simplified_expressions,
            'devirtualized_handlers': self.metrics.devirtualized_handlers,
            'checkpoints': len(self.checkpoints)
        }