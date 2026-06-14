"""
Parallel mutation execution engine.

Provides concurrent execution of independent mutation passes
to improve performance on multi-core systems.

Features:
- Dependency-aware scheduling
- Work stealing for load balancing
- Checkpoint-based rollback
- Progress tracking
- Binary file locking for concurrent writes
"""

import logging
import tempfile
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.binary_file_lock import BinaryFileLock
from r2morph.core.parallel_checkpointing import has_failures
from r2morph.core.parallel_execution_summary import build_parallel_results_summary
from r2morph.core.parallel_pass_execution import execute_checkpointed_pass
from r2morph.core.parallel_planner import (
    DependencyResolver,
    PassResult,
    PassStatus,
)
from r2morph.core.parallel_planner import (
    ExecutionPlan as _ExecutionPlan,
)
from r2morph.core.parallel_planner import (
    PassDependency as _PassDependency,
)
from r2morph.core.parallel_rollback import rollback_pass_checkpoint
from r2morph.protocols import MutationPassProtocol

ExecutionPlan = _ExecutionPlan
PassDependency = _PassDependency

logger = logging.getLogger(__name__)


class ParallelMutationEngine:
    """
    Execute mutation passes in parallel where possible.

    Uses dependency resolution to determine which passes can run
    concurrently and which must run sequentially.

    For process-based parallelism, uses BinaryFileLock to coordinate
    writes to the same binary file across processes.
    """

    def __init__(
        self,
        binary: Binary,
        max_workers: int = 4,
        use_checkpoints: bool = True,
        checkpoint_dir: Path | None = None,
        use_file_lock: bool = True,
        lock_timeout: float = 30.0,
    ) -> None:
        """
        Initialize parallel mutation engine.

        Args:
            binary: Binary to mutate
            max_workers: Maximum parallel workers
            use_checkpoints: Whether to create checkpoints before each pass
            checkpoint_dir: Directory for checkpoints
            use_file_lock: Whether to use file locking for concurrent writes
            lock_timeout: Timeout for acquiring file lock (seconds)
        """
        self.binary = binary
        self.max_workers = max_workers
        self.use_checkpoints = use_checkpoints
        self.checkpoint_dir = checkpoint_dir or Path(tempfile.mkdtemp())
        self.use_file_lock = use_file_lock
        self.lock_timeout = lock_timeout
        self.resolver = DependencyResolver()
        self._lock = threading.Lock()
        # In-process serialization of binary mutation. BinaryFileLock only
        # coordinates across processes (one instance per process, and its
        # acquire() is a no-op for a second thread once _locked is set), so
        # it cannot prevent concurrent ThreadPoolExecutor pass-workers from
        # mutating the shared, non-thread-safe Binary/r2pipe at once.
        self._binary_mutation_lock = threading.Lock()
        self._results: dict[str, PassResult] = {}
        self._stop_on_error = False
        self._file_lock: BinaryFileLock | None = None

        if use_file_lock and binary:
            self._file_lock = BinaryFileLock(binary.path, timeout=lock_timeout)

    def _add_result(self, pass_name: str, result: PassResult) -> None:
        """Thread-safe result addition."""
        with self._lock:
            self._results[pass_name] = result

    def _get_results_copy(self) -> dict[str, PassResult]:
        """Thread-safe results copy."""
        with self._lock:
            return self._results.copy()

    def execute(
        self,
        passes: list[MutationPassProtocol],
        stop_on_error: bool = True,
        progress_callback: Callable[[str, float], None] | None = None,
    ) -> dict[str, PassResult]:
        """
        Execute mutation passes in parallel where possible.

        Args:
            passes: List of mutation passes to execute
            stop_on_error: Stop execution on first error
            progress_callback: Optional callback for progress updates

        Returns:
            Dictionary of pass name to PassResult
        """
        self._stop_on_error = stop_on_error
        with self._lock:
            self._results.clear()

        conflicts = self.resolver.check_conflicts(passes)
        if conflicts and stop_on_error:
            for name1, name2 in conflicts:
                logger.warning(f"Conflicting passes: {name1} conflicts with {name2}")
                logger.warning("Consider running these passes separately")

        plan: ExecutionPlan = self.resolver.resolve(passes)

        logger.info(f"Execution plan: {len(plan.stages)} stages")
        for i, stage in enumerate(plan.stages):
            logger.info(f"  Stage {i + 1}: {stage}")

        try:
            if self.use_checkpoints:
                self._save_checkpoint("__initial__")

            for stage_num, stage in enumerate(plan.stages):
                if self._stop_on_error and has_failures(self._results):
                    logger.warning("Stopping due to previous errors")
                    break

                if not stage:
                    logger.warning(f"Empty stage {stage_num} encountered in execution plan")
                    continue

                logger.info(f"Executing stage {stage_num + 1}/{len(plan.stages)}: {stage}")

                if len(stage) == 1:
                    pass_name = stage[0]
                    matching_passes = [p for p in passes if p.name == pass_name]
                    if not matching_passes:
                        logger.error(f"Pass {pass_name} not found in pass list")
                        self._add_result(
                            pass_name,
                            PassResult(pass_name=pass_name, status=PassStatus.FAILED, error="Pass not found"),
                        )
                        continue
                    pass_obj = matching_passes[0]
                    result = self._execute_pass(pass_obj, progress_callback)
                    self._add_result(pass_name, result)
                else:
                    stage_results = self._execute_stage(stage, passes, stage_num, len(plan.stages), progress_callback)
                    for name, res in stage_results.items():
                        self._add_result(name, res)

        except Exception as e:
            logger.error(f"Parallel execution failed: {e}")
            raise

        return self._results

    def _execute_stage(
        self,
        stage: list[str],
        passes: list[MutationPassProtocol],
        stage_num: int,
        total_stages: int,
        progress_callback: Callable[[str, float], None] | None,
    ) -> dict[str, PassResult]:
        """Execute all passes in a stage in parallel."""
        results: dict[str, PassResult] = {}
        pass_map = {p.name: p for p in passes}

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(stage))) as executor:
            futures: dict[Future, str] = {}

            for pass_name in stage:
                if pass_name not in pass_map:
                    continue
                pass_obj = pass_map[pass_name]
                future = executor.submit(
                    self._execute_pass,
                    pass_obj,
                    progress_callback,
                )
                futures[future] = pass_name

            for future in as_completed(futures):
                pass_name = futures[future]
                try:
                    result = future.result()
                    results[pass_name] = result
                except Exception as e:
                    logger.error(f"Pass {pass_name} raised exception: {e}")
                    results[pass_name] = PassResult(
                        pass_name=pass_name,
                        status=PassStatus.FAILED,
                        error=str(e),
                    )

        return results

    def _execute_pass(
        self,
        pass_obj: MutationPassProtocol,
        progress_callback: Callable[[str, float], None] | None,
    ) -> PassResult:
        """Execute a single mutation pass with optional file locking."""
        return execute_checkpointed_pass(
            binary=self.binary,
            pass_obj=pass_obj,
            checkpoint_dir=self.checkpoint_dir,
            use_checkpoints=self.use_checkpoints,
            file_lock=self._file_lock,
            use_file_lock=self.use_file_lock,
            binary_mutation_lock=self._binary_mutation_lock,
            progress_callback=progress_callback,
            logger=logger,
        )

    def rollback(self, pass_name: str) -> bool:
        """
        Rollback to checkpoint before a specific pass.

        Args:
            pass_name: Name of pass to rollback before

        Returns:
            True if rollback successful
        """
        return rollback_pass_checkpoint(
            binary_path=self.binary.path,
            result=self._results.get(pass_name),
            logger=logger,
        )

    def get_results_summary(self) -> dict[str, Any]:
        """Get summary of all execution results."""
        return build_parallel_results_summary(self._results)


def execute_parallel(
    binary: Binary,
    passes: list[MutationPassProtocol],
    max_workers: int = 4,
    stop_on_error: bool = True,
) -> dict[str, PassResult]:
    """
    Convenience function for parallel mutation execution.

    Args:
        binary: Binary to mutate
        passes: List of mutation passes
        max_workers: Maximum parallel workers
        stop_on_error: Stop on first error

    Returns:
        Dictionary of pass name to PassResult
    """
    engine = ParallelMutationEngine(binary, max_workers=max_workers)
    return engine.execute(passes, stop_on_error=stop_on_error)
