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

import concurrent.futures
import logging
import threading
import time
from dataclasses import replace
from typing import Any

from .iterative_simplifier_models import (
    SimplificationMetrics,
    SimplificationPass,
    SimplificationPhase,
    SimplificationResult,
    SimplificationStrategy,
)
from .iterative_simplifier_passes import CFOSimplificationPass, MBASimplificationPass, VMDevirtualizationPass

logger = logging.getLogger(__name__)


class IterativeSimplifier:
    """
    Iterative simplification engine for obfuscated binaries.

    Applies multiple deobfuscation techniques in an iterative manner
    until convergence is reached or maximum iterations are hit.
    """

    def __init__(self, binary: Any = None) -> None:
        """Initialize the iterative simplifier."""
        self.binary = binary
        self.strategy = SimplificationStrategy.ADAPTIVE
        self.max_iterations = 20
        self.convergence_threshold = 0.01  # 1% improvement threshold
        self.timeout = 300  # 5 minutes default timeout
        self.parallel_execution = False

        # Simplification passes
        self.passes = [CFOSimplificationPass(), MBASimplificationPass(), VMDevirtualizationPass()]

        # Progress tracking
        self.metrics = SimplificationMetrics()
        self.checkpoints: list[dict[str, Any]] = []

        logger.info("Initialized iterative simplifier")

    def simplify(
        self,
        binary: Any = None,
        strategy: SimplificationStrategy | None = None,
        max_iterations: int | None = None,
        timeout: int | None = None,
    ) -> SimplificationResult:
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
                success=False, strategy_used=self.strategy, errors=["No binary provided for simplification"]
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

                # Check for convergence. A zero prev_complexity means there is
                # no measurable complexity to reduce (a clean or trivial binary
                # with no detected functions/patterns/MBA/VM): treat it as
                # trivially converged instead of dividing by zero.
                current_complexity = self._calculate_complexity(context)
                if prev_complexity == 0.0:
                    improvement = 0.0
                else:
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
                warnings=validation_result.get("warnings", []),
            )

        except Exception as e:
            logger.error(f"Iterative simplification failed: {e}")
            return SimplificationResult(
                success=False,
                strategy_used=self.strategy,
                errors=[f"Simplification failed: {str(e)}"],
                metrics=self.metrics,
            )

    def _analyze_binary(self) -> dict[str, Any]:
        """Analyze the binary to gather initial information."""
        context: dict[str, Any] = {
            "functions": [],
            "mba_expressions": [],
            "vm_dispatchers": [],
            "obfuscation_patterns": [],
            "initial_complexity": 0,
        }

        try:
            if hasattr(self.binary, "get_functions"):
                functions = self.binary.get_functions()
                context["functions"] = [f.get("offset", 0) for f in functions]

            # Initial complexity calculation
            context["initial_complexity"] = len(context["functions"])

            logger.debug(f"Analyzed binary: {len(context['functions'])} functions")

        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")

        return context

    def _preprocess_binary(self, context: dict[str, Any]) -> dict[str, Any]:
        """Preprocess the binary for simplification."""
        try:
            # Identify obfuscation patterns
            from ..detection import ObfuscationDetector

            detector = ObfuscationDetector()
            if hasattr(detector, "analyze_binary"):
                detection_result = detector.analyze_binary(self.binary)
                context["obfuscation_patterns"] = detection_result.obfuscation_techniques

                if detection_result.vm_detected:
                    # Look for VM dispatchers
                    context["vm_dispatchers"] = self._find_vm_dispatchers()

                if detection_result.mba_detected:
                    # Extract MBA expressions
                    context["mba_expressions"] = self._extract_mba_expressions()

        except Exception as e:
            logger.error(f"Preprocessing failed: {e}")

        return context

    def _apply_passes_sequential(self, context: dict[str, Any]) -> bool:
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

    def _apply_passes_parallel(self, context: dict[str, Any]) -> bool:
        """Apply simplification passes in parallel."""
        iteration_changes = False

        # Every pass drives the one shared radare2 instance
        # (self.binary.r2), which is a single duplex pipe and not
        # thread-safe. Without serialization, concurrent commands
        # interleave on the pipe so a worker can read another worker's
        # response, silently corrupting analysis, and the desync trips
        # the BrokenPipe respawn path (churning transient r2 processes).
        # Hold a lock so only one worker drives radare2 at a time.
        r2_lock = threading.Lock()

        def _run(pass_obj: SimplificationPass) -> tuple[bool, dict[str, Any]]:
            with r2_lock:
                return pass_obj.apply(self.binary, context.copy())

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = []

            for pass_obj in self.passes:
                future = executor.submit(_run, pass_obj)
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

    def _calculate_complexity(self, context: dict[str, Any]) -> float:
        """Calculate current complexity metric."""
        try:
            # Simple complexity metric based on various factors
            base_complexity = len(context.get("functions", []))

            # Add complexity from obfuscation patterns
            pattern_complexity = len(context.get("obfuscation_patterns", []))

            # Add MBA expression complexity
            mba_complexity = len(context.get("mba_expressions", []))

            # Add VM complexity
            vm_complexity = len(context.get("vm_dispatchers", [])) * 10

            total_complexity = base_complexity + pattern_complexity + mba_complexity + vm_complexity
            return float(total_complexity)

        except Exception:
            return 1.0

    def _adjust_strategy(self, improvement: float, iteration: int) -> None:
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

    def _create_checkpoint(self, context: dict[str, Any]) -> dict[str, Any]:
        """Create a checkpoint of the current state."""
        return {
            "iteration": self.metrics.iteration,
            "timestamp": time.time(),
            "context": context.copy(),
            # Snapshot the metrics. self.metrics is mutated in place every
            # iteration, so storing the live reference would make every
            # checkpoint alias the latest metrics and rollback_to_checkpoint
            # a no-op.
            "metrics": replace(self.metrics),
        }

    def _update_metrics(self, context: dict[str, Any]) -> None:
        """Update simplification metrics."""
        mba_results = context.get("mba_results", [])
        vm_results = context.get("vm_results", [])

        self.metrics.simplified_expressions += len(mba_results)
        self.metrics.devirtualized_handlers += sum(len(vm.handlers) for vm in vm_results if hasattr(vm, "handlers"))

        # Calculate complexity reduction
        initial = context.get("initial_complexity", 1)
        current = self._calculate_complexity(context)
        self.metrics.complexity_reduction = (initial - current) / initial

    def _optimize_result(self, context: dict[str, Any]) -> dict[str, Any]:
        """Perform final optimizations."""
        try:
            # Remove redundant information
            context["optimization_applied"] = True

            # Clean up intermediate data if needed
            if len(context.get("checkpoints", [])) > 5:
                context["checkpoints"] = context["checkpoints"][-5:]

        except Exception as e:
            logger.error(f"Result optimization failed: {e}")

        return context

    def _validate_result(self, context: dict[str, Any]) -> dict[str, Any]:
        """Validate the simplification result."""
        validation: dict[str, Any] = {"valid": True, "warnings": []}

        try:
            # Check if we achieved meaningful simplification
            if self.metrics.complexity_reduction < 0.01:
                validation["warnings"].append("Very low complexity reduction achieved")

            # Check for potential issues
            if len(context.get("errors", [])) > 0:
                validation["warnings"].append("Errors occurred during simplification")

        except Exception as e:
            validation["valid"] = False
            validation["warnings"].append(f"Validation failed: {e}")

        return validation

    # Heuristic threshold above which a function's basic-block count is high
    # enough that it is likely a VM dispatcher loop (VMProtect/Themida-style
    # switch dispatchers commonly have hundreds of blocks; legitimate
    # functions rarely exceed this).
    _VM_DISPATCHER_BLOCK_THRESHOLD = 40

    def _find_vm_dispatchers(self) -> list[int]:
        """Locate candidate VM dispatcher addresses by basic-block count.

        Returns offsets of functions whose basic-block count exceeds
        ``_VM_DISPATCHER_BLOCK_THRESHOLD``. This is a coarse heuristic
        intended to feed downstream analysis; it does not confirm a
        dispatcher, only that the function is structurally suspicious.
        """
        if not hasattr(self.binary, "get_functions") or not hasattr(self.binary, "get_basic_blocks"):
            return []

        try:
            functions = self.binary.get_functions()
        except Exception as exc:
            logger.warning("Cannot enumerate functions for VM dispatcher search: %s", exc)
            return []

        dispatchers: list[int] = []
        for func in functions:
            offset = func.get("offset")
            if not isinstance(offset, int):
                continue
            try:
                blocks = self.binary.get_basic_blocks(offset)
            except Exception as exc:
                logger.debug("Skipping function 0x%x while searching dispatchers: %s", offset, exc)
                continue
            if len(blocks) > self._VM_DISPATCHER_BLOCK_THRESHOLD:
                dispatchers.append(offset)

        return dispatchers

    def _extract_mba_expressions(self) -> list[str]:
        """Extract MBA expressions from the binary.

        Real extraction requires walking arithmetic-instruction chains and
        symbolically lifting them to expressions. Until that walker exists,
        return an empty list rather than hardcoded placeholders, which
        previously caused MBASimplificationPass to operate on fake data.
        """
        return []

    def rollback_to_checkpoint(self, checkpoint_index: int = -1) -> bool:
        """Rollback to a previous checkpoint."""
        try:
            if not self.checkpoints:
                logger.warning("No checkpoints available for rollback")
                return False

            checkpoint = self.checkpoints[checkpoint_index]

            # Restore state from checkpoint data
            self.metrics = checkpoint["metrics"]

            logger.info(f"Rolled back to checkpoint at iteration {checkpoint['iteration']}")
            return True

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False

    def get_progress_report(self) -> dict[str, Any]:
        """Get current progress report."""
        return {
            "iteration": self.metrics.iteration,
            "complexity_reduction": self.metrics.complexity_reduction,
            "execution_time": self.metrics.execution_time,
            "simplified_expressions": self.metrics.simplified_expressions,
            "devirtualized_handlers": self.metrics.devirtualized_handlers,
            "checkpoints": len(self.checkpoints),
        }
