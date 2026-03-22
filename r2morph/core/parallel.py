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
import threading
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable
from pathlib import Path
import time
import sys

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)

# Platform-specific locking
if sys.platform == "win32":
    try:
        import msvcrt

        HAS_MSVCRT = True
    except ImportError:
        HAS_MSVCRT = False
    FCNTL_AVAILABLE = False
else:
    try:
        import fcntl

        FCNTL_AVAILABLE = True
    except ImportError:
        FCNTL_AVAILABLE = False
    HAS_MSVCRT = False


class PassStatus(Enum):
    """Status of a mutation pass."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


@dataclass
class PassResult:
    """Result of executing a mutation pass."""

    pass_name: str
    status: PassStatus
    result: dict[str, Any] | None = None
    error: str | None = None
    duration_seconds: float = 0.0
    mutations_applied: int = 0
    checkpoint_path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pass_name": self.pass_name,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
            "mutations_applied": self.mutations_applied,
            "checkpoint_path": str(self.checkpoint_path) if self.checkpoint_path else None,
        }


@dataclass
class PassDependency:
    """Declares dependencies between mutation passes."""

    pass_name: str
    requires: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    optional: bool = False


@dataclass
class ExecutionPlan:
    """Execution plan for parallel mutations."""

    passes: list[MutationPass]
    dependencies: dict[str, PassDependency] = field(default_factory=dict)
    stages: list[list[str]] = field(default_factory=list)

    def get_stage(self, pass_name: str) -> int:
        """Get the stage number for a pass."""
        for i, stage in enumerate(self.stages):
            if pass_name in stage:
                return i
        return -1


class DependencyResolver:
    """Resolves dependencies between mutation passes."""

    # Known pass dependencies
    KNOWN_DEPENDENCIES: dict[str, PassDependency] = {
        "nop": PassDependency("nop", requires=[], conflicts=[]),
        "substitute": PassDependency(
            "substitute",
            requires=[],
            conflicts=[],  # Can run with other independent passes
        ),
        "register": PassDependency(
            "register",
            requires=[],
            conflicts=["substitute"],  # Register substitution conflicts with instruction substitution
        ),
        "block": PassDependency(
            "block",
            requires=[],
            conflicts=["nop", "substitute", "register"],  # Block reordering conflicts with most passes
        ),
        "cff": PassDependency(
            "cff",
            requires=[],
            conflicts=["block", "nop"],  # Control flow flattening conflicts
        ),
        "dead-code": PassDependency(
            "dead-code",
            requires=[],
            conflicts=[],  # Dead code injection is mostly independent
        ),
        "opaque": PassDependency(
            "opaque",
            requires=[],
            conflicts=["cff"],  # Opaque predicates conflict with CFF
        ),
    }

    def __init__(self, custom_dependencies: dict[str, PassDependency] | None = None) -> None:
        """
        Initialize dependency resolver.

        Args:
            custom_dependencies: Custom dependencies to add/override
        """
        self.dependencies = dict(self.KNOWN_DEPENDENCIES)
        if custom_dependencies:
            self.dependencies.update(custom_dependencies)

    def resolve(self, passes: list[MutationPass]) -> ExecutionPlan:
        """
        Resolve dependencies and create execution plan.

        Args:
            passes: List of mutation passes

        Returns:
            ExecutionPlan with staged passes
        """
        pass_names = {p.name for p in passes}

        for p in passes:
            if p.name not in self.dependencies:
                self.dependencies[p.name] = PassDependency(p.name, requires=[], conflicts=[])

        stages: list[list[str]] = []
        scheduled: set[str] = set()

        while len(scheduled) < len(pass_names):
            stage: list[str] = []

            for pass_name in pass_names:
                if pass_name in scheduled:
                    continue

                dep = self.dependencies.get(pass_name, PassDependency(pass_name))

                can_schedule = True
                for req in dep.requires:
                    if req not in scheduled:
                        can_schedule = False
                        break

                if can_schedule:
                    for conflict in dep.conflicts:
                        if conflict in scheduled:
                            can_schedule = False
                            break

                if can_schedule:
                    stage.append(pass_name)

            if not stage:
                remaining = pass_names - scheduled
                logger.warning(f"Circular dependency detected. Forcing remaining passes: {remaining}")
                stage = list(remaining)

            scheduled.update(stage)
            stages.append(stage)

        return ExecutionPlan(
            passes=passes,
            dependencies=self.dependencies,
            stages=stages,
        )

    def check_conflicts(self, passes: list[MutationPass]) -> list[tuple[str, str]]:
        """
        Check for conflicts between passes.

        Args:
            passes: List of mutation passes

        Returns:
            List of (pass1, pass2) conflict pairs
        """
        conflicts: list[tuple[str, str]] = []
        pass_names = [p.name for p in passes]

        for i, name1 in enumerate(pass_names):
            for name2 in pass_names[i + 1 :]:
                dep1 = self.dependencies.get(name1, PassDependency(name1))
                dep2 = self.dependencies.get(name2, PassDependency(name2))

                if name2 in dep1.conflicts or name1 in dep2.conflicts:
                    conflicts.append((name1, name2))

        return conflicts


class BinaryFileLock:
    """
    File-based lock for coordinating binary writes across processes.

    Provides exclusive locking for binary modifications to prevent
    race conditions when multiple processes attempt to write to
    the same binary file.
    """

    def __init__(self, binary_path: Path, timeout: float = 30.0) -> None:
        """
        Initialize binary file lock.

        Args:
            binary_path: Path to the binary file
            timeout: Maximum time to wait for lock acquisition (seconds)
        """
        self.binary_path = Path(binary_path)
        self.lock_path = self.binary_path.with_suffix(self.binary_path.suffix + ".lock")
        self.timeout = timeout
        self._lock_file = None
        self._lock_dir_path = None
        self._locked = False

    def acquire(self, blocking: bool = True) -> bool:
        """
        Acquire the file lock.

        Args:
            blocking: Whether to block until lock is acquired

        Returns:
            True if lock was acquired, False otherwise
        """
        if self._locked:
            return True

        lock_file: Any = None
        try:
            lock_file = open(self.lock_path, "w")

            if FCNTL_AVAILABLE:
                lock_type = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB

                start_time = time.time()
                while True:
                    try:
                        fcntl.flock(lock_file.fileno(), lock_type)
                        self._lock_file = lock_file
                        self._locked = True
                        logger.debug(f"Acquired lock for {self.binary_path}")
                        return True
                    except (IOError, OSError):
                        if not blocking:
                            lock_file.close()
                            return False
                        if time.time() - start_time > self.timeout:
                            logger.warning(f"Lock acquisition timeout for {self.binary_path}")
                            lock_file.close()
                            return False
                        time.sleep(0.1)
            elif HAS_MSVCRT:
                start_time = time.time()
                while True:
                    try:
                        __import__("msvcrt").locking(
                            lock_file.fileno(), msvcrt.LK_NBLCK if not blocking else msvcrt.LK_LOCK, 1
                        )
                        self._lock_file = lock_file
                        self._locked = True
                        logger.debug(f"Acquired lock for {self.binary_path}")
                        return True
                    except (IOError, OSError):
                        if not blocking:
                            lock_file.close()
                            return False
                        if time.time() - start_time > self.timeout:
                            logger.warning(f"Lock acquisition timeout for {self.binary_path}")
                            lock_file.close()
                            return False
                        time.sleep(0.1)
            else:
                logger.warning("No native locking available, using directory-based fallback")
                lock_dir = self.lock_path.with_suffix(".lockdir")
                self._lock_dir_path = lock_dir
                start_time = time.time()
                while True:
                    try:
                        lock_dir.mkdir(parents=True, exist_ok=False)
                        self._lock_file = lock_file
                        self._locked = True
                        logger.debug(f"Acquired lock for {self.binary_path}")
                        return True
                    except FileExistsError:
                        if not blocking:
                            lock_file.close()
                            return False
                        if time.time() - start_time > self.timeout:
                            logger.warning(f"Lock acquisition timeout for {self.binary_path}")
                            lock_file.close()
                            return False
                        time.sleep(0.1)
                    except Exception as e:
                        logger.error(f"Failed to acquire lock for {self.binary_path}: {e}")
                        lock_file.close()
                        return False

        except Exception as e:
            logger.error(f"Failed to acquire lock for {self.binary_path}: {e}")
            if lock_file:
                lock_file.close()
            return False

    def release(self) -> None:
        """Release the file lock."""
        if self._locked:
            try:
                if FCNTL_AVAILABLE and self._lock_file:
                    fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                elif HAS_MSVCRT and self._lock_file:
                    __import__("msvcrt").locking(self._lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                elif self._lock_dir_path:
                    if self._lock_dir_path.exists():
                        self._lock_dir_path.rmdir()
                self._locked = False
                logger.debug(f"Released lock for {self.binary_path}")
            except Exception as e:
                logger.error(f"Failed to release lock for {self.binary_path}: {e}")
            finally:
                if self._lock_file:
                    self._lock_file.close()
                    self._lock_file = None
                self._lock_dir_path = None

    def __enter__(self) -> "BinaryFileLock":
        """Context manager entry."""
        acquired = self.acquire()
        if not acquired:
            raise TimeoutError(f"Failed to acquire lock for {self.binary_path} within {self.timeout}s")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.release()

    def is_locked(self) -> bool:
        """Check if lock is currently held."""
        return self._locked


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
        passes: list[MutationPass],
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

        plan = self.resolver.resolve(passes)

        logger.info(f"Execution plan: {len(plan.stages)} stages")
        for i, stage in enumerate(plan.stages):
            logger.info(f"  Stage {i + 1}: {stage}")

        try:
            if self.use_checkpoints:
                self._save_checkpoint("__initial__")

            for stage_num, stage in enumerate(plan.stages):
                if self._stop_on_error and self._has_failures():
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
        passes: list[MutationPass],
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
        pass_obj: MutationPass,
        progress_callback: Callable[[str, float], None] | None,
    ) -> PassResult:
        """Execute a single mutation pass with optional file locking."""
        pass_name = pass_obj.name
        start_time = time.time()

        try:
            if progress_callback:
                progress_callback(pass_name, 0.0)

            if self.use_checkpoints:
                checkpoint_path = self._save_checkpoint(pass_name)
            else:
                checkpoint_path = None

            logger.debug(f"Executing pass: {pass_name}")

            # Acquire file lock before modifying binary if using file locking
            if self._file_lock and self.use_file_lock:
                acquired = self._file_lock.acquire()
                if not acquired:
                    logger.error(f"Failed to acquire file lock for pass {pass_name}")
                    return PassResult(
                        pass_name=pass_name,
                        status=PassStatus.FAILED,
                        error="Failed to acquire file lock",
                        duration_seconds=time.time() - start_time,
                    )

            try:
                result = pass_obj.apply(self.binary)
            finally:
                # Always release the lock after pass execution
                if self._file_lock and self._file_lock.is_locked():
                    self._file_lock.release()

            duration = time.time() - start_time
            mutations_applied = result.get("mutations_applied", 0) if result else 0

            if progress_callback:
                progress_callback(pass_name, 1.0)

            return PassResult(
                pass_name=pass_name,
                status=PassStatus.COMPLETED,
                result=result,
                duration_seconds=duration,
                mutations_applied=mutations_applied,
                checkpoint_path=checkpoint_path,
            )

        except Exception as e:
            logger.error(f"Pass {pass_name} failed: {e}")
            duration = time.time() - start_time

            # Ensure lock is released on failure
            if self._file_lock and self._file_lock.is_locked():
                self._file_lock.release()

            return PassResult(
                pass_name=pass_name,
                status=PassStatus.FAILED,
                error=str(e),
                duration_seconds=duration,
            )

    def _save_checkpoint(self, pass_name: str) -> Path:
        """Save a checkpoint of the current binary state."""
        checkpoint_path = self.checkpoint_dir / f"checkpoint_{pass_name}.bin"
        try:
            import shutil

            shutil.copy2(self.binary.path, checkpoint_path)
            logger.debug(f"Saved checkpoint: {checkpoint_path}")
            return checkpoint_path
        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {e}")
            return Path("")

    def _has_failures(self) -> bool:
        """Check if any pass has failed."""
        return any(r.status == PassStatus.FAILED for r in self._results.values())

    def rollback(self, pass_name: str) -> bool:
        """
        Rollback to checkpoint before a specific pass.

        Args:
            pass_name: Name of pass to rollback before

        Returns:
            True if rollback successful
        """
        result = self._results.get(pass_name)
        if not result or not result.checkpoint_path:
            logger.warning(f"No checkpoint for pass: {pass_name}")
            return False

        try:
            import shutil

            shutil.copy2(result.checkpoint_path, self.binary.path)
            result.status = PassStatus.ROLLED_BACK
            logger.info(f"Rolled back to checkpoint before {pass_name}")
            return True
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False

    def get_results_summary(self) -> dict[str, Any]:
        """Get summary of all execution results."""
        completed = sum(1 for r in self._results.values() if r.status == PassStatus.COMPLETED)
        failed = sum(1 for r in self._results.values() if r.status == PassStatus.FAILED)
        skipped = sum(1 for r in self._results.values() if r.status == PassStatus.SKIPPED)
        rolled_back = sum(1 for r in self._results.values() if r.status == PassStatus.ROLLED_BACK)

        total_mutations = sum(r.mutations_applied for r in self._results.values())
        total_duration = sum(r.duration_seconds for r in self._results.values())

        return {
            "total_passes": len(self._results),
            "completed": completed,
            "failed": failed,
            "skipped": skipped,
            "rolled_back": rolled_back,
            "total_mutations": total_mutations,
            "total_duration_seconds": total_duration,
            "passes": {name: result.to_dict() for name, result in self._results.items()},
        }


def execute_parallel(
    binary: Binary,
    passes: list[MutationPass],
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
