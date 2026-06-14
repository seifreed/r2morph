"""
Parallel mutation execution engine.

Executes mutation passes in parallel on independent regions
to speed up mutation processing on multi-core systems.
"""

import logging
import multiprocessing
import threading
from typing import Any

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass, MutationRecord
from r2morph.mutations.parallel_executor_models import MutationResult, MutationTask, ParallelStats
from r2morph.mutations.parallel_executor_planning import build_task_plans
from r2morph.mutations.parallel_executor_runtime import execute_parallel_runs
from r2morph.mutations.parallel_executor_speedup import estimate_parallel_speedup

# File-level write lock to prevent concurrent binary corruption
_binary_write_lock = threading.Lock()

logger = logging.getLogger(__name__)


class ParallelMutator:
    """
    Executes mutation passes in parallel on independent function regions.

    This class divides the binary into function-level chunks and applies
    mutations in parallel when the mutations are independent (don't share
    dependencies).

    Note: This is experimental and requires careful handling of binary
    state. Writes must be serialized to avoid corruption.

    Config options:
        - max_workers: Maximum worker threads (default: CPU count)
        - chunk_size: Functions per chunk (default: 10)
        - timeout: Timeout per task in seconds (default: 300)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize parallel mutator.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.max_workers = self.config.get("max_workers", multiprocessing.cpu_count())
        self.chunk_size = self.config.get("chunk_size", 10)
        self.timeout = self.config.get("timeout", 300)

    def _create_tasks(
        self,
        passes: list[MutationPass],
        functions: list[dict[str, Any]],
    ) -> list[MutationTask]:
        """
        Create mutation tasks from passes and functions.

        Divides functions into chunks and creates tasks for each pass.

        Args:
            passes: List of mutation passes
            functions: List of function dictionaries

        Returns:
            List of MutationTask objects
        """
        return [
            MutationTask(
                pass_name=plan.pass_name,
                pass_instance=plan.pass_instance,
                function_addresses=plan.function_addresses,
                config=plan.config,
            )
            for plan in build_task_plans(passes, functions, self.chunk_size)
        ]

    def _execute_task(
        self,
        task: MutationTask,
        binary_path: str,
    ) -> MutationResult:
        """
        Execute a single mutation task.

        Note: This creates a fresh Binary instance per task to avoid
        threading issues with r2pipe.

        Args:
            task: Mutation task to execute
            binary_path: Path to binary file

        Returns:
            MutationResult with task outcome
        """
        result = MutationResult()

        try:
            # Serialize file writes to prevent concurrent binary corruption
            with _binary_write_lock, Binary(binary_path, flags=["-2"], writable=True) as binary:
                binary.analyze()

                functions = [f for f in binary.get_functions() if f.get("addr", 0) in task.function_addresses]

                if not functions:
                    result.success = True
                    return result

                pass_result = task.pass_instance.apply(binary)

                result.success = pass_result.get("success", True)
                result.mutations_applied = pass_result.get("mutations_applied", 0)
                result.metadata = pass_result

                records = task.pass_instance.get_records()
                result.records = records

        except Exception as e:
            result.success = False
            result.errors.append(f"Task failed: {e}")
            logger.error(f"Parallel task {task.pass_name} failed: {e}")

        return result

    def execute_parallel(
        self,
        passes: list[MutationPass],
        binary: Any,
    ) -> tuple[list[MutationRecord], ParallelStats]:
        """Execute mutation passes in parallel."""
        return execute_parallel_runs(
            passes,
            binary,
            max_workers=self.max_workers,
            timeout=self.timeout,
            create_tasks=self._create_tasks,
            execute_task=self._execute_task,
            stats_factory=ParallelStats,
            logger=logger,
        )

    def estimate_speedup(
        self,
        passes: list[MutationPass],
        function_count: int,
    ) -> float:
        """Estimate potential speedup from parallel execution."""
        return estimate_parallel_speedup(
            passes,
            function_count=function_count,
            max_workers=self.max_workers,
            chunk_size=self.chunk_size,
        )


def create_parallel_executor(config: dict[str, Any] | None = None) -> ParallelMutator:
    """
    Create a parallel mutation executor.

    Args:
        config: Configuration dictionary

    Returns:
        ParallelMutator instance
    """
    return ParallelMutator(config)
